package scrubber

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
)

type ScrubResult struct {
	Encoding string
	Count    int
}

type Scrubber struct {
	patterns []pattern
}

type pattern struct {
	encoded  []byte
	encoding string
}

var redacted = []byte("[REDACTED]")

func New(secrets [][]byte) *Scrubber {
	var patterns []pattern

	for _, secret := range secrets {
		if len(secret) == 0 {
			continue
		}

		patterns = append(patterns, pattern{
			encoded:  secret,
			encoding: "literal",
		})

		patterns = append(patterns, pattern{
			encoded:  []byte(base64.StdEncoding.EncodeToString(secret)),
			encoding: "base64",
		})

		patterns = append(patterns, pattern{
			encoded:  []byte(url.QueryEscape(string(secret))),
			encoding: "urlencode",
		})

		patterns = append(patterns, pattern{
			encoded:  []byte(hex.EncodeToString(secret)),
			encoding: "hex",
		})
	}

	return &Scrubber{patterns: patterns}
}

func (s *Scrubber) Scrub(body []byte) ([]byte, []ScrubResult) {
	result := body
	var results []ScrubResult

	for _, p := range s.patterns {
		if len(p.encoded) == 0 {
			continue
		}

		count := bytes.Count(result, p.encoded)
		if count > 0 {
			result = bytes.ReplaceAll(result, p.encoded, redacted)
			results = append(results, ScrubResult{
				Encoding: p.encoding,
				Count:    count,
			})
		}
	}

	return result, results
}
