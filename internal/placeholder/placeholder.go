package placeholder

import (
	"regexp"
	"strings"
)

type Match struct {
	Start      int
	End        int
	Qualifier  string
	Identifier string
}

type ReplaceResult struct {
	Qualifier  string
	Identifier string
	Replaced   bool
	Reason     string
}

type LookupFunc func(qualifier, identifier string) ([]byte, []string, error)

var (
	namePattern = regexp.MustCompile(`__SAFE_SECRET__NAME__([A-Z0-9_]+)`)
	idPattern   = regexp.MustCompile(`__SAFE_SECRET__ID__([a-f0-9-]+)`)
)

func Scan(data []byte) []Match {
	var matches []Match

	nameMatches := namePattern.FindAllSubmatchIndex(data, -1)
	for _, m := range nameMatches {
		matches = append(matches, Match{
			Start:      m[0],
			End:        m[1],
			Qualifier:  "NAME",
			Identifier: string(data[m[2]:m[3]]),
		})
	}

	idMatches := idPattern.FindAllSubmatchIndex(data, -1)
	for _, m := range idMatches {
		matches = append(matches, Match{
			Start:      m[0],
			End:        m[1],
			Qualifier:  "ID",
			Identifier: string(data[m[2]:m[3]]),
		})
	}

	return matches
}

func Replace(data []byte, dstHost string, lookup LookupFunc) ([]byte, []ReplaceResult) {
	matches := Scan(data)
	if len(matches) == 0 {
		return data, nil
	}

	results := make([]ReplaceResult, len(matches))
	output := make([]byte, len(data))
	copy(output, data)

	for i := len(matches) - 1; i >= 0; i-- {
		match := matches[i]
		result := ReplaceResult{
			Qualifier:  match.Qualifier,
			Identifier: match.Identifier,
			Replaced:   false,
		}

		secretValue, allowedHosts, err := lookup(match.Qualifier, match.Identifier)
		if err != nil {
			result.Reason = "not_found"
			results[i] = result
			continue
		}

		if !hostMatches(dstHost, allowedHosts) {
			result.Reason = "host_blocked"
			results[i] = result
			continue
		}

		before := output[:match.Start]
		after := output[match.End:]
		output = append(before, secretValue...)
		output = append(output, after...)

		result.Replaced = true
		results[i] = result
	}

	return output, results
}

func hostMatches(dstHost string, allowedHosts []string) bool {
	for _, allowed := range allowedHosts {
		if dstHost == allowed {
			return true
		}
		if strings.HasSuffix(dstHost, "."+allowed) {
			return true
		}
	}
	return false
}
