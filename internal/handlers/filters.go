package handlers

import (
	"html/template"
	"net/url"
)

// filterChip is one clickable option in a filter row. Href already carries
// every other active filter, so following a chip changes exactly one thing.
type filterChip struct {
	Label    string
	Href     template.URL
	Active   bool
	Disabled bool
	Title    string
}

// activeFilter is one applied filter, rendered as a chip whose link removes it.
type activeFilter struct {
	Label string
	Href  template.URL
}

// chipHref returns path plus base with key set to value, or with key removed
// when value is empty. Paging is dropped: changing a filter invalidates the
// current page number.
func chipHref(path string, base url.Values, key, value string) template.URL {
	q := make(url.Values, len(base)+1)
	for k, v := range base {
		q[k] = append([]string(nil), v...)
	}
	q.Del("page")
	if value == "" {
		q.Del(key)
	} else {
		q.Set(key, value)
	}
	if len(q) == 0 {
		return template.URL(path)
	}
	return template.URL(path + "?" + q.Encode())
}

// chipRow builds a row of filter chips for key. Each option pairs a value with
// its label; an empty value is the "no filter" option.
func chipRow(path string, base url.Values, key, current string, opts [][2]string) []filterChip {
	row := make([]filterChip, 0, len(opts))
	for _, o := range opts {
		row = append(row, filterChip{
			Label:  o[1],
			Href:   chipHref(path, base, key, o[0]),
			Active: o[0] == current,
		})
	}
	return row
}
