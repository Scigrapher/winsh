//go:build windows

package agent

// Windows-specific agent discovery.
//
// PuTTY's Pageant does not listen on a fixed name.  Since 0.76 it creates
// \\.\pipe\pageant.<user>.<hash>, where the hash is derived from the logon
// user's SID by a formula that has varied between releases and is not part of
// any specification.  A client that hard-codes \\.\pipe\pageant.pipe therefore
// never finds a modern Pageant, so winsh enumerates the pipe namespace instead
// and matches the pageant.* prefix.
//
// Enumeration alone would be unsafe: named pipes are a machine-global name
// space, so any local process could create \\.\pipe\pageant.blahb.whatever and
// be handed private-key signatures to forge.  PuTTY guards the other direction
// by checking that the pipe it connects to is owned by the current user, and
// winsh applies the same rule to every discovered candidate before a single
// byte of key material crosses it.  Pipes whose name was discovered by globbing
// are rejected unless the owner SID equals our own.

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	advapi32             = syscall.NewLazyDLL("advapi32.dll")
	procGetSecurityInfo  = advapi32.NewProc("GetSecurityInfo")
	procEqualSid         = advapi32.NewProc("EqualSid")
	procOpenProcessToken = advapi32.NewProc("OpenProcessToken")
	procGetTokenInfo     = advapi32.NewProc("GetTokenInformation")
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	// LocalFree is exported by kernel32, not advapi32; asking the wrong DLL
	// makes the LazyProc panic on first use.
	procLocalFree         = kernel32.NewProc("LocalFree")
	procWaitNamedPipe     = kernel32.NewProc("WaitNamedPipeW")
	procImpersonateNamedC = kernel32.NewProc("ImpersonateNamedPipeClient")
)

const (
	seKernelObjectType = 6
	ownerSecurityInfo  = 0x00000001
	tokenQuery         = 0x0008
	tokenUserClass     = 1
	genericRead        = 0x80000000
	genericWrite       = 0x40000000
	fileShareReadWrite = 0x00000003
	openExisting       = 3
	// QoS selectors for CreateFile, so the server may identify us.
	securitySQOSPresent    = 0x00080000
	securityIdentification = 0x00000001
	maxDiscoveredPageants  = 8
	pageantPipeNamePrefix  = "pageant."

	// Win32 error codes Go's syscall package does not name. Comparing these
	// instead of printing a generic "open:" is what lets --list-keys say "no
	// agent is listening here" for a pipe that was never created, rather than
	// the misleading timeout message that has wasted so many afternoons.
	errorFileNotFound = syscall.Errno(2)
	errorAccessDenied = syscall.Errno(5)
	errorPipeBusy     = syscall.Errno(231)
)

// pageantPipePrefix is what the enumerated names must start with.  The
// legacy Git-for-Windows fork uses the bare name pageant.pipe, which is
// accepted by Candidates() separately.
func platformCandidates() []Candidate {
	var out []Candidate
	for _, name := range enumeratePipes(pageantPipeNamePrefix) {
		out = append(out, Candidate{
			Name:        "Pageant (discovered)",
			Path:        `\\.\pipe\` + name,
			Kind:        "pipe",
			VerifyOwner: true,
		})
	}
	return out
}

// enumeratePipes lists named pipes whose name starts with prefix.
func enumeratePipes(prefix string) []string {
	// The named-pipe namespace does not treat "." as a literal separator in a
	// search pattern, so the glob stops at the punctuation and the prefix is
	// re-checked below.
	glob := strings.TrimRight(prefix, ".")
	pattern, err := syscall.UTF16PtrFromString(`\\.\pipe\` + glob + `*`)
	if err != nil {
		return nil
	}
	var data syscall.Win32finddata
	handle, err := syscall.FindFirstFile(pattern, &data)
	if err != nil {
		return nil
	}
	defer syscall.FindClose(handle)

	var out []string
	add := func() bool {
		name := syscall.UTF16ToString(data.FileName[:])
		if name == "" {
			return true
		}
		if !strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
			return true
		}
		// Listing is side-effect free on purpose.  Ownership is proven later,
		// on the handle that Dial actually uses: probing each candidate with a
		// separate open would burn an instance of servers that publish only
		// one, which includes Pageant.
		out = append(out, name)
		return len(out) < maxDiscoveredPageants
	}
	if !add() {
		return out
	}
	for {
		if err := syscall.FindNextFile(handle, &data); err != nil {
			return out
		}
		if !add() {
			return out
		}
	}
}

func init() { verifyPipeOwnership = verifyPipeOwnedByCurrentUser }

// verifyPipeOwnedByCurrentUser reports whether the named pipe behind f is owned
// by the user running this process.  Every failure is treated as "not owned",
// so a pipe whose security cannot be established is never negotiated with.
func verifyPipeOwnedByCurrentUser(f *os.File) error {
	h := syscall.Handle(f.Fd())
	owner, sd, err := getObjectOwner(h)
	if sd != 0 {
		defer procLocalFree.Call(sd)
	}
	if err != nil {
		return fmt.Errorf("cannot read pipe owner: %w", err)
	}
	mine, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("cannot read our own SID: %w", err)
	}
	r, _, _ := procEqualSid.Call(owner, uintptr(unsafe.Pointer(mine)))
	if r == 0 {
		return errors.New("pipe is not owned by the current user")
	}
	return nil
}

func getObjectOwner(h syscall.Handle) (sid uintptr, sd uintptr, err error) {
	var owner, group, dacl, sacl uintptr
	var secDesc uintptr
	r, _, e := procGetSecurityInfo.Call(
		uintptr(h),
		seKernelObjectType,
		ownerSecurityInfo,
		uintptr(unsafe.Pointer(&owner)),
		uintptr(unsafe.Pointer(&group)),
		uintptr(unsafe.Pointer(&dacl)),
		uintptr(unsafe.Pointer(&sacl)),
		uintptr(unsafe.Pointer(&secDesc)),
	)
	if r != 0 {
		return 0, 0, fmt.Errorf("GetSecurityInfo: %v (code %d)", e, r)
	}
	if owner == 0 {
		if secDesc != 0 {
			procLocalFree.Call(secDesc)
		}
		return 0, 0, fmt.Errorf("pipe has no owner SID")
	}
	return owner, secDesc, nil
}

// currentProcess is the pseudo-handle returned by GetCurrentProcess(), which
// is always (HANDLE)-1 for the calling process.
const currentProcessHandle = ^uintptr(0)

// tokenUser mirrors the unexported syscall.TOKEN_USER: a SID pointer followed
// by its attributes.
type tokenUser struct {
	SidAndAttributes struct {
		Sid        *uint32
		Attributes uint32
	}
}

func currentUserSID() (sid *uint32, err error) {
	var token syscall.Handle
	r, _, e := procOpenProcessToken.Call(
		currentProcessHandle,
		tokenQuery,
		uintptr(unsafe.Pointer(&token)),
	)
	if r == 0 {
		return nil, fmt.Errorf("OpenProcessToken: %v", e)
	}
	defer syscall.CloseHandle(token)

	var needed uint32
	procGetTokenInfo.Call(uintptr(token), tokenUserClass, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 || needed > 1<<16 {
		return nil, fmt.Errorf("GetTokenInformation reported an implausible size %d", needed)
	}
	buf := make([]byte, needed)
	r, _, e = procGetTokenInfo.Call(
		uintptr(token),
		tokenUserClass,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r == 0 {
		return nil, fmt.Errorf("GetTokenInformation: %v", e)
	}
	var tu tokenUser
	// The buffer holds a TOKEN_USER whose first field is a pointer to the SID.
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&tu)), unsafe.Sizeof(tu)), buf)
	if tu.SidAndAttributes.Sid == nil {
		return nil, fmt.Errorf("token has no user SID")
	}
	return tu.SidAndAttributes.Sid, nil
}

// dialPipe opens a client handle on a named pipe and wraps it as an os.File so
// the rest of the package treats every transport the same way.
//
// Two details matter, and both were learned the hard way.
//
// First, CreateFile queues when every instance of the pipe is busy, so an agent
// that is mid-conversation with someone else (or wedged behind a modal dialog)
// would otherwise park winsh at startup with no timeout at all.  WaitNamedPipe
// is therefore consulted with a bounded wait first; it reports failure as soon
// as the budget runs out, and an unavailable agent is only a soft failure.
//
// Second, the QoS flags.  Pageant authenticates whoever connects by
// impersonating the client, and an impersonation-level connection requires the
// server process to hold SeImpersonatePrivilege, which an ordinary user process
// does not.  Asking for Identification is sufficient for a "same user?" check
// and is the level PuTTY's own client requests.
func dialPipe(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(
		p,
		genericRead|genericWrite,
		0,
		nil,
		openExisting,
		securitySQOSPresent|securityIdentification,
		0,
	)
	if errno, ok := err.(syscall.Errno); ok && errno == errorPipeBusy {
		// Every instance is taken: the agent exists and is serving somebody
		// else. Queue for a bounded time and try once more.
		r, _, _ := procWaitNamedPipe.Call(
			uintptr(unsafe.Pointer(p)),
			uintptr(pipeProbeTimeout/time.Millisecond),
		)
		if r == 0 {
			return nil, fmt.Errorf("every agent instance was busy for %v", pipeProbeTimeout)
		}
		h, err = syscall.CreateFile(
			p, genericRead|genericWrite, 0, nil, openExisting,
			securitySQOSPresent|securityIdentification, 0,
		)
	}
	if err != nil {
		// Say what the failure actually was. Reporting a two-second timeout
		// for a pipe that was never created in the first place sent more than
		// one investigation looking for a hung agent that did not exist.
		if errno, ok := err.(syscall.Errno); ok && errno == errorFileNotFound {
			return nil, fmt.Errorf("no agent is listening here")
		}
		if errno, ok := err.(syscall.Errno); ok && errno == errorAccessDenied {
			return nil, fmt.Errorf("access denied opening the pipe")
		}
		return nil, fmt.Errorf("open: %w", err)
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		syscall.CloseHandle(h)
		return nil, fmt.Errorf("could not wrap pipe handle for %s", path)
	}
	return f, nil
}

// pipeProbeTimeout bounds how long discovery will consider a candidate.
const pipeProbeTimeout = 2 * time.Second
