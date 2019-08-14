package fetcher

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/url"

	"github.com/PuerkitoBio/goquery"
	"github.com/deepin-cve/tracker/pkg/db"
)

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
			cve.FixUrgency()
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
