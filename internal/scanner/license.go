package scanner

import (
	"regexp"
	"strings"
	"time"
)

// LicenseInfo describes a recognized license.
type LicenseInfo struct {
	SPDX string
	Name string
	OSI  bool
}

// KnownLicenses maps SPDX identifiers to human names / OSI approval status.
// This is intentionally a curated subset of the most common OSI licenses.
var KnownLicenses = map[string]LicenseInfo{
	"MIT":          {"MIT", "MIT License", true},
	"Apache-2.0":   {"Apache-2.0", "Apache License 2.0", true},
	"BSD-2-Clause": {"BSD-2-Clause", "BSD 2-Clause \"Simplified\" License", true},
	"BSD-3-Clause": {"BSD-3-Clause", "BSD 3-Clause \"New\" / \"Revised\" License", true},
	"ISC":          {"ISC", "ISC License", true},
	"GPL-2.0":      {"GPL-2.0", "GNU General Public License v2.0", true},
	"GPL-3.0":      {"GPL-3.0", "GNU General Public License v3.0", true},
	"LGPL-2.1":     {"LGPL-2.1", "GNU Lesser General Public License v2.1", true},
	"LGPL-3.0":     {"LGPL-3.0", "GNU Lesser General Public License v3.0", true},
	"AGPL-3.0":     {"AGPL-3.0", "GNU Affero General Public License v3.0", true},
	"MPL-2.0":      {"MPL-2.0", "Mozilla Public License 2.0", true},
	"Unlicense":    {"Unlicense", "The Unlicense", true},
	"CC0-1.0":      {"CC0-1.0", "Creative Commons Zero v1.0 Universal", false},
	"Zlib":         {"Zlib", "zlib License", true},
	"BSL-1.0":      {"BSL-1.0", "Boost Software License 1.0", true},
	"Artistic-2.0": {"Artistic-2.0", "Artistic License 2.0", true},
	"WTFPL":        {"WTFPL", "Do What The F*ck You Want To Public License", false},
	"0BSD":         {"0BSD", "BSD Zero Clause License", true},
}

type licenseDetector struct {
	spdx   string
	all    []string // all phrases must be present
	anyNot []string // none of these may be present (disambiguation)
}

// Ordered most-specific-first so that, e.g., BSD-3-Clause wins over BSD-2.
var licenseDetectors = []licenseDetector{
	{"AGPL-3.0", []string{"gnu affero general public license", "version 3"}, nil},
	{"LGPL-3.0", []string{"gnu lesser general public license", "version 3"}, nil},
	{"LGPL-2.1", []string{"gnu lesser general public license", "version 2.1"}, nil},
	{"GPL-3.0", []string{"gnu general public license", "version 3"}, []string{"lesser", "affero"}},
	{"GPL-2.0", []string{"gnu general public license", "version 2"}, []string{"lesser", "affero"}},
	{"Apache-2.0", []string{"apache license", "version 2.0"}, nil},
	{"MPL-2.0", []string{"mozilla public license", "version 2.0"}, nil},
	{"BSD-3-Clause", []string{"redistribution and use in source and binary forms", "neither the name of"}, nil},
	{"BSD-2-Clause", []string{"redistribution and use in source and binary forms"}, []string{"neither the name of", "endorse or promote"}},
	{"ISC", []string{"permission to use, copy, modify, and/or distribute this software for any purpose"}, nil},
	{"MIT", []string{"permission is hereby granted, free of charge"}, nil},
	{"Unlicense", []string{"free and unencumbered software released into the public domain"}, nil},
	{"CC0-1.0", []string{"creative commons", "cc0 1.0"}, nil},
	{"Zlib", []string{"altered source versions must be plainly marked"}, nil},
	{"BSL-1.0", []string{"boost software license", "version 1.0"}, nil},
	{"Artistic-2.0", []string{"artistic license", "version 2.0"}, nil},
	{"WTFPL", []string{"do what the fuck you want"}, nil},
	{"0BSD", []string{"permission to use, copy, modify, and/or distribute this software for any purpose", "no warranty"}, []string{"copyright notice"}},
}

func normalizeLicenseText(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	// Collapse runs of whitespace to single spaces to be resilient to wrap.
	return strings.Join(strings.Fields(s), " ")
}

// DetectLicense attempts to identify the license in the supplied text.
// It returns the SPDX identifier and true when recognized.
func DetectLicense(text string) (LicenseInfo, bool) {
	norm := normalizeLicenseText(text)
	if norm == "" {
		return LicenseInfo{}, false
	}
	for _, d := range licenseDetectors {
		if !containsAll(norm, d.all) {
			continue
		}
		if containsAny(norm, d.anyNot) {
			continue
		}
		if info, ok := KnownLicenses[d.spdx]; ok {
			return info, true
		}
		return LicenseInfo{SPDX: d.spdx, Name: d.spdx}, true
	}
	// Fallback: explicit "MIT License" / "Apache License" mentions.
	if strings.Contains(norm, "mit license") {
		return KnownLicenses["MIT"], true
	}
	return LicenseInfo{}, false
}

func containsAll(s string, needles []string) bool {
	for _, n := range needles {
		if !strings.Contains(s, n) {
			return false
		}
	}
	return true
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

var reYear = regexp.MustCompile(`\b(1[89]\d{2}|[2-9]\d{3})\b`)

// LicenseYears extracts up to two distinct years near a "copyright" marker and
// reports whether the detected range looks reasonable. It is deliberately
// permissive: it only flags clearly implausible values.
func LicenseYears(text string) (years []int, reasonable bool) {
	norm := strings.ToLower(text)
	idx := strings.Index(norm, "copyright")
	window := text
	if idx >= 0 {
		end := idx + 160
		if end > len(text) {
			end = len(text)
		}
		window = text[idx:end]
	}
	seen := map[int]bool{}
	for _, m := range reYear.FindAllString(window, -1) {
		var y int
		for _, c := range m {
			y = y*10 + int(c-'0')
		}
		if !seen[y] {
			seen[y] = true
			years = append(years, y)
		}
	}
	if len(years) == 0 {
		return nil, true
	}
	now := time.Now().Year()
	reasonable = true
	for _, y := range years {
		if y < 1970 || y > now+1 {
			reasonable = false
		}
	}
	if len(years) >= 2 {
		lo, hi := years[0], years[1]
		if lo > hi {
			reasonable = false
		}
	}
	return years, reasonable
}

var (
	reCopyrightLine = regexp.MustCompile(`(?i)copyright`)
	reSPDXHeader    = regexp.MustCompile(`(?i)SPDX-License-Identifier`)
)

// HasSPDXHeader reports whether content contains an SPDX-License-Identifier tag.
func HasSPDXHeader(content string) bool { return reSPDXHeader.MatchString(content) }

// HasCopyrightNotice reports whether content contains a copyright notice.
func HasCopyrightNotice(content string) bool { return reCopyrightLine.MatchString(content) }
