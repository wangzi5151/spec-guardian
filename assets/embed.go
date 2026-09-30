// Package assets exposes files embedded into the Spec-Guardian binary.
package assets

import _ "embed"

// ReportHTML is the single-file HTML report template. It is embedded so the
// released binary needs no external files at runtime.
//
//go:embed html-template/report.html
var ReportHTML string
