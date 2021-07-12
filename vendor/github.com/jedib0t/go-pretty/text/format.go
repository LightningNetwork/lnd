package text

import "strings"

// Format denotes the "case" to use for text.
type Format int

// Format enumerations
const (
	FormatDefault Format = iota // default_Case
	FormatLower                 // lower
	FormatTitle                 // Title
	FormatUpper                 // UPPER
)

// Apply converts the text as directed.
func (tc Format) Apply(text string) string {
	switch tc {
	case FormatLower:
		return strings.ToLower(text)
	case FormatTitle:
		return strings.Title(text)
	case FormatUpper:
		return strings.ToUpper(text)
	default:
		return text
	}
}
