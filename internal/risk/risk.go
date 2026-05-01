package risk

// Level represents an ordered risk level.
type Level int

const (
	None   Level = 0
	Low    Level = 1
	Medium Level = 2
	High   Level = 3
)

// Parse converts a string to a Level. Returns None for unknown values.
func Parse(s string) Level {
	switch s {
	case "low":
		return Low
	case "medium":
		return Medium
	case "high":
		return High
	default:
		return None
	}
}

// Valid returns true if s is a valid risk level string.
func Valid(s string) bool {
	switch s {
	case "none", "low", "medium", "high":
		return true
	}
	return false
}

// GTE returns true if l is greater than or equal to threshold.
func GTE(l Level, threshold Level) bool {
	return l >= threshold
}
