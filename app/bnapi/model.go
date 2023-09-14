package bnapi

const (
	activeOngoing string = "active_ongoing"
)

// ValidatorState holds information about the state of a validator, as returned by the Beacon Node API.
// We redact some fields off it for our usage.
// See: https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidator
type ValidatorState struct {
	ExecutionOptimistic bool               `json:"execution_optimistic,omitempty"`
	Finalized           bool               `json:"finalized,omitempty"`
	Data                ValidatorStateData `json:"data,omitempty"`
}

// ValidatorStateData holds a given validator index and status string.
type ValidatorStateData struct {
	Index  string `json:"index,omitempty"`
	Status string `json:"status,omitempty"`
}

// ShouldProcess returns true when vs.Status is "active_ongoing", validator index is not zero,
// execution is not optimistic and information comes from a finalized state.
func (vs ValidatorState) ShouldProcess() bool {
	return (!vs.ExecutionOptimistic && vs.Finalized) &&
		vs.Data.Status == activeOngoing && vs.Data.Index != "0"
}

// SignedExitMessage is an ExitMessage that has been signed.
type SignedExitMessage struct {
	Message   ExitMessage
	Signature []byte
}

// ExitMessage is the Ethereum exit message struct.
type ExitMessage struct {
	Epoch          string `json:"epoch,omitempty"`
	ValidatorIndex string `json:"validator_index,omitempty"`
}
