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
	/* if err == nil {
		return score, nil
	} */
	return score, nil
	// fmt.Println("Failed to fetch cve score3.0:",err)
	// return getScoreFromCVSS2(dom, filepath.Base(url))
}

func getScoreFromCVSS3(dom *goquery.Document, id string) (*db.CVEScore, error) {
	var score = db.CVEScore{ID: id, CVSS: "3.0"}
	v, err := getElementText(dom, "a[data-testid=vuln-cvss3-panel-score]")
	if err != nil {
		v, err = getElementText(dom, "a[data-testid=vuln-cvss3-cna-panel-score]")
		if err != nil {
			v, err = getElementText(dom, "a[data-testid=vuln-cvss3-panel-score-na]")
			if err != nil {
				return nil, err
			}
		}
	}
	scores := strings.Split(v, " ")
	if len(scores) != 2 {
		return &score, nil
	}
	score.Score = strToFloat64(scores[0])

	v, err = getElementText(dom, "a[data-testid=vuln-cvss3-panel-score]")
	if err != nil {
		v, err = getElementText(dom, "a[data-testid=vuln-cvss3-cna-panel-score]")
		if err != nil {
			v, err = getElementText(dom, "a[data-testid=vuln-cvss3-panel-score-na]")
			if err != nil {
				return nil, err
			}
		}
	}
	score.ScoreSeverity = scores[1]
	return &score, nil
}

func getScoreFromCVSS2(dom *goquery.Document, id string) (*db.CVEScore, error) {
	var score = db.CVEScore{ID: id, CVSS: "2.0"}
	v, err := getElementText(dom, "a[class=label label-warning]")
	if err != nil {
		return nil, err
	}
	v = strings.Split(v, " ")[0]
	score.Score = strToFloat64(v)

	v, err = getElementText(dom, "a[class=label label-warning]")
	if err != nil {
		return nil, err
	}
	score.ScoreSeverity = v

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
