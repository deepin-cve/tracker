package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

type cveStatus struct {
	ID      string
	Package string
	Version string
	Release string
	Status  string
}

const urlPrefix = "https://security-tracker.debian.org/tracker"

func fetchIDStatus(id, release string) (*cveStatus, error) {
	resp, err := http.Get(urlPrefix + "/" + id)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", id, string(data))
	}

	dom, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	tmp := dom.Find("h1").Text()
	if strings.TrimSpace(tmp) != id {
		return nil, fmt.Errorf("not found '%s'", id)
	}
	return doQueryStatus(dom, id, release), nil
}

func doQueryStatus(dom *goquery.Document, id, release string) *cveStatus {
	var infos = []*cveStatus{}
	idx := 0
	isTarget := false
	isFound := 0
	dom.Find("table").Each(func(tbIdx int, tableItem *goquery.Selection) {
		if isTarget {
			return
		}
		tableItem.Find("tr").Each(func(trIdx int, trItem *goquery.Selection) {
			trItem.Find("th").Each(func(thIdx int, thItem *goquery.Selection) {
				fmt.Println("Th text:", thItem.Text())
				if isTarget {
					return
				}
				isTarget = thItem.Text() == "Source Package"
			})
			if !isTarget {
				return
			}
			if idx == 0 {
				infos = append(infos, &cveStatus{ID: id})
				idx++
			}
			isRelease := false
			trItem.Find("td").Each(func(tdIdx int, tdItem *goquery.Selection) {
				if isFound == 3 {
					infos = append(infos, &cveStatus{ID: id})
					idx++
					isFound = 0
					isRelease = false
					return
				}

				name := tdItem.Text()
				fmt.Println("Td text:", name, isFound, isRelease, idx, tdIdx)
				if tdIdx == 0 {
					if isFound == 0 && len(name) != 0 {
						infos[idx-1].Package = strings.TrimRight(name, " (PTS)")
						return
					}
				}
				if tdIdx == 1 && strings.Contains(name, release) &&
					len(infos[idx-1].Package) != 0 {
					isRelease = true
				}

				if !isRelease {
					return
				}

				switch tdIdx {
				case 1:
					infos[idx-1].Release = strings.ReplaceAll(name, ",", ";")
				case 2:
					infos[idx-1].Version = name
				case 3:
					infos[idx-1].Status = name
				}
				isFound++
			})
		})
	})

	var info = cveStatus{ID: id}
	for idx, tmp := range infos {
		if len(tmp.Package) == 0 {
			continue
		}
		if idx == 0 {
			info.Package = tmp.Package
			info.Version = tmp.Version
			info.Status = tmp.Status
			info.Release = tmp.Release
		} else {
			info.Package += "/" + tmp.Package
			info.Version += "/" + tmp.Version
			info.Status += "/" + tmp.Status
			info.Release += "/" + tmp.Release
		}
	}
	return &info
}
