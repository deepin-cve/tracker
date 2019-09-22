package fetcher

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/deepin-cve/tracker/pkg/db"
)

// FetchScore get cve score from NVD
func FetchScore(url string) (*db.CVEScore, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, string(data))
	}

	// dom, err := goquery.NewDocument(url) // maybe get empty page content
	dom, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	score, err := getScoreFromCVSS3(dom, filepath.Base(url))
	if err == nil {
		return score, nil
	}
	return getScoreFromCVSS2(dom, filepath.Base(url))
}

func getScoreFromCVSS3(dom *goquery.Document, id string) (*db.CVEScore, error) {
	var score = db.CVEScore{ID: id, CVSS: "3.0"}
	v, err := getElementText(dom, "span[data-testid=vuln-cvssv3-base-score]")
	if err != nil {
		return nil, err
	}
	score.Score = strToFloat64(v)

	v, err = getElementText(dom, "span[data-testid=vuln-cvssv3-base-score-severity]")
	if err != nil {
		return nil, err
	}
	score.ScoreSeverity = v

	v, err = getElementText(dom, "span[data-testid=vuln-cvssv3-vector]")
	if err != nil {
		return nil, err
	}
	list := strings.Split(v, "\n")
	score.Vector = strings.TrimSpace(list[0])

	v, err = getElementText(dom, "span[data-testid=vuln-cvssv3-impact-score]")
	if err != nil {
		return nil, err
	}
	score.ImpactScore = strToFloat64(v)

	v, err = getElementText(dom, "span[data-testid=vuln-cvssv3-exploitability-score]")
	if err != nil {
		return nil, err
	}
	score.ExploitabilityScore = strToFloat64(v)
	return &score, nil
}

func getScoreFromCVSS2(dom *goquery.Document, id string) (*db.CVEScore, error) {
	var score = db.CVEScore{ID: id, CVSS: "2.0"}
	v, err := getElementText(dom, "span[data-testid=vuln-cvssv2-base-score]")
	if err != nil {
		return nil, err
	}
	score.Score = strToFloat64(v)

	v, err = getElementText(dom, "span[data-testid=vuln-cvssv2-base-score-severity]")
	if err != nil {
		return nil, err
	}
	score.ScoreSeverity = v

	v, err = getElementText(dom, "span[data-testid=vuln-cvssv2-vector]")
	if err != nil {
		return nil, err
	}
	list := strings.Split(v, "\n")
	score.Vector = strings.TrimSpace(list[0])

	v, err = getElementText(dom, "span[data-testid=vuln-cvssv2-impact-score]")
	if err != nil {
		return nil, err
	}
	score.ImpactScore = strToFloat64(v)

	v, err = getElementText(dom, "span[data-testid=vuln-cvssv2-exploitability-score]")
	if err != nil {
		return nil, err
	}
	score.ExploitabilityScore = strToFloat64(v)
	return &score, nil
}

func getElementText(dom *goquery.Document, ele string) (string, error) {
	sel := dom.Find(ele)
	if sel == nil || len(sel.Nodes) == 0 {
		return "", fmt.Errorf("no '%s' found in dom", ele)
	}
	return strings.TrimSpace(sel.Text()), nil
}

func strToFloat64(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}
