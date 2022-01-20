package xtls

import (
	"strings"
)

func FixDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(d), ".")
}

func FixDomains(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, FixDomain(v))
	}
	return out
}
