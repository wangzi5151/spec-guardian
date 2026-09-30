package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/wangzi5151/spec-guardian/assets"
)

const dataPlaceholder = "__SPECGUARDIAN_DATA__"

// WriteHTML renders a fully self-contained single-file HTML report. No network
// requests, CDNs or external assets are used, so the file can be opened
// directly from disk.
func WriteHTML(w io.Writer, r *Report) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	// json.Marshal escapes <, > and & by default, making the payload safe to
	// embed inside a <script> element.
	tmpl := assets.ReportHTML
	if !strings.Contains(tmpl, dataPlaceholder) {
		return fmt.Errorf("html template is missing the %s placeholder", dataPlaceholder)
	}
	out := strings.Replace(tmpl, dataPlaceholder, string(data), 1)
	_, err = io.WriteString(w, out)
	return err
}
