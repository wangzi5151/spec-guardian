package rules

import (
	"github.com/wangzi5151/spec-guardian/internal/scanner"
)

// deadLink groups the occurrences of a dead URL.
type deadLink struct {
	url    string
	result string
	files  []scanner.Link
}

func groupLinks(ctx *Context, wantArchived bool) []deadLink {
	if !ctx.LinkEnabled || len(ctx.LinkResults) == 0 {
		return nil
	}
	var order []string
	byURL := map[string]*deadLink{}
	for _, l := range ctx.Links {
		res, ok := ctx.LinkResults[l.URL]
		if !ok {
			continue
		}
		if wantArchived {
			if !res.Archived {
				continue
			}
		} else if res.OK || res.Skipped {
			continue
		}
		dl, ok := byURL[l.URL]
		if !ok {
			dl = &deadLink{url: l.URL, result: res.FormatResult()}
			byURL[l.URL] = dl
			order = append(order, l.URL)
		}
		dl.files = append(dl.files, l)
	}
	out := make([]deadLink, 0, len(order))
	for _, u := range order {
		out = append(out, *byURL[u])
	}
	return out
}

func checkDeadLinks(ctx *Context) []scanner.Finding {
	groups := groupLinks(ctx, false)
	const capLimit = 200
	var findings []scanner.Finding
	for _, g := range groups {
		first := g.files[0]
		msg := "Dead link: " + g.url + " (" + g.result + ")"
		if len(g.files) > 1 {
			msg += "; referenced in " + itoa(len(g.files)) + " places"
		}
		findings = append(findings, scanner.Finding{
			File:    first.File,
			Line:    first.Line,
			Message: msg,
		})
		if len(findings) >= capLimit {
			break
		}
	}
	return findings
}

func checkArchivedLinks(ctx *Context) []scanner.Finding {
	groups := groupLinks(ctx, true)
	const capLimit = 200
	var findings []scanner.Finding
	for _, g := range groups {
		res := ctx.LinkResults[g.url]
		first := g.files[0]
		findings = append(findings, scanner.Finding{
			File:    first.File,
			Line:    first.Line,
			Message: "Dead link has an archive snapshot: " + res.ArchiveURL,
		})
		if len(findings) >= capLimit {
			break
		}
	}
	return findings
}
