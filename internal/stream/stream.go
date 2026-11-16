// Package stream defines the contract for a synchronizable state that the SSP
// transport copies around: a client's input stream, or a server's terminal.
//
// It lives in its own package so that the emulator, the input stream, and the
// transport can all agree on the interface without importing one another.
package stream

// State is a versioned, diffable piece of session state.
//
// The contract matters for correctness: DiffFrom(e) must return bytes that,
// applied to a clone of e, reproduce s exactly.  The transport relies on that
// to rebuild any state in its window.
type State interface {
	// Clone returns an independent copy.
	Clone() State
	// DiffFrom returns instructions turning existing into this state.  An
	// empty result means "no change" or "no safe diff exists".
	DiffFrom(existing State) []byte
	// InitDiff returns the diff from a freshly created empty state.
	InitDiff() []byte
	// ApplyString mutates this state by applying a diff.
	ApplyString(diff []byte) error
	// Subtract drops a prefix that the peer is known to already hold.  It is
	// an optimisation for append-only streams and a no-op for others.
	Subtract(prefix State)
	// Equal reports whether two states are indistinguishable.
	Equal(State) bool
}
