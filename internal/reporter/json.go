package reporter

import (
	"encoding/json"
	"io"
)

// WriteJSON writes an indented JSON representation of the report.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
