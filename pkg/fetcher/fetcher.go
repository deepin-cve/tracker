package fetcher

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/url"

	"github.com/PuerkitoBio/goquery"
	"github.com/deepin-cve/tracker/pkg/db"
)

// Filter urgency level
type FilterUrgency string

// Filter scope
type FilterScope string

const (
	// Filter tracker filter
	FilterUrgencyHigh           FilterUrgency = "high_urgency"
	FilterUrgencyMedium                       = "medium_urgency"
	FilterUrgencyLow                          = "low_urgency"
	FilterUrgencyUnimportant                  = "unimportant_urgency"
	FilterUrgencyNotYetAssigned               = "unassigned_urgency"
	FilterUrgencyEndOfLife                    = "endoflife_urgency"
)

const (
	// Filter scope list
	FilterScopeHideRemote   FilterScope = "remote"
	FilterScopeHideLocal                = "locale"
	FilterScopeHideUnclear              = "unclear"
	FilterScopeUndetermined             = "undetermined_issues"
	FilterScopeNoDSA                    = "nodsa"
	FilterScopeIgnore                   = "noignored"
	FilterScopePostponed                = "nopostponed"
)

func (filter FilterUrgency) String() string {
	var ret string
	switch filter {
	case FilterUrgencyHigh:
		ret = "high"
	case FilterUrgencyMedium:
		ret = "medium"
	case FilterUrgencyLow:
		ret = "low"
	case FilterUrgencyUnimportant:
		ret = "unimportant"
	case FilterUrgencyNotYetAssigned:
		ret = "not yet assigned"
	case FilterUrgencyEndOfLife:
		ret = "end of life"
	default:
		ret = "unknown"
	}
	return ret
}

func (filter FilterScope) String() string {
	var ret string
	switch filter {
	case FilterScopeHideRemote:
		ret = "hide remote"
	case FilterScopeHideLocal:
		ret = "hide local"
	case FilterScopeHideUnclear:
		ret = "hide unclear"
	case FilterScopeUndetermined:
		ret = "include issues to be checked"
	case FilterScopeNoDSA:
		ret = "include issues tagged <on-dsa>"
	case FilterScopeIgnore:
		ret = "include issues tagged <no-ignored>"
	case FilterScopePostponed:
		ret = "include issues tagged <postponed>"
	default:
		ret = "unknown"
	}
	return ret
}

func Fetch(uri string, filterList []string) (db.DebianCVEList, error) {
	var values = make(url.Values)
	values["filter"] = filterList
	params := values.Encode()
	if len(params) != 0 {
		uri += "?" + params
	}
	fmt.Println("Fetch uri:", uri)

	doc, err := goquery.NewDocument(uri)
	if err != nil {
		fmt.Println("Failed to new document tree:", err)
		return nil, err
	}

	// only a table
	tableElm := doc.Find("table")
	if tableElm == nil {
		fmt.Println("No table exists")
		return nil, fmt.Errorf("invalid uri: no table exists")
	}
	var cveList db.DebianCVEList
	tableElm.Find("tr").Each(func(rowIdx int, rowEle *goquery.Selection) {
		// ignore header
		var cve db.DebianCVE
		rowEle.Find("td").Each(func(cellIdx int, cellEle *goquery.Selection) {
			switch cellIdx {
			case 0:
				cve.Package = cellEle.Text()
			case 1:
				cve.ID = cellEle.Text()
			case 2:
				cve.Urgency = cellEle.Text()
			case 3:
				cve.Remote = cellEle.Text()
			}
		})
		if len(cve.ID) != 0 {
			cveList = append(cveList, &cve)
		}
	})

	cveList.FixPackage()
	// cveList.Dump()
	return cveList, nil
}

// FetchFromFile parse html document from file
func FetchFromFile(filename string) {
	datas, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Failed to read file:", err)
		return
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(datas))
	if err != nil {
		fmt.Println("Failed to new document tree:", err)
		return
	}

	doc.Find("table").Each(func(i int, tableEle *goquery.Selection) {
		tableEle.Find("tr").Each(func(ii int, rowEle *goquery.Selection) {
			var headers []string
			var rows []string
			rowEle.Find("th").Each(func(iii1 int, thEle *goquery.Selection) {
				headers = append(headers, thEle.Text())
			})
			rowEle.Find("td").Each(func(iii2 int, tdEle *goquery.Selection) {
				var row = tdEle.Text()
				tdEle.Find("a").Each(func(iiii int, aEle *goquery.Selection) {
					href, _ := aEle.Attr("href")
					if href != "" {
						row += " - " + href
					}
				})
				rows = append(rows, row)
			})
			if len(headers) != 0 {
				fmt.Println(ii, ", headers:", headers)
			}
			fmt.Println(ii, ", data:", rows)
		})
	})
}
