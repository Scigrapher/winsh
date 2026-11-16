//go:build !windows

package agent

import (
	"fmt"
	"os"
	"time"
)

// platformCandidates has nothing to discover off Windows, where there is no
// named-pipe namespace to search.
func platformCandidates() []Candidate { return nil }

// dialPipe is never reached on this platform, but the shared code path needs
// it to exist.
func dialPipe(path string) (*os.File, error) {
	return nil, fmt.Errorf("agent: named pipes are only available on Windows (%s)", path)
}

// pipeProbeTimeout bounds how long discovery will consider a candidate.
const pipeProbeTimeout = 2 * time.Second
