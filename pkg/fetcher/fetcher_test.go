package fetcher

import (
	"testing"
)

func TestFetcherFromFile(t *testing.T) {
	FetchFromFile("./testdata/high_undeterminded.html")
	Fetch("https://security-tracker.debian.org/tracker/status/release/stable", []string{"high_urgency"})
}
