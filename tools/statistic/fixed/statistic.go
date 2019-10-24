package main

import (
	"flag"
	"fmt"

	"github.com/deepin-cve/tracker/pkg/db"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var (
	dbFile   = flag.String("db", "", "the cve db file")
	minScore = flag.Float64("min", 0, "the min score")
	maxScore = flag.Float64("max", 0, "the max score")
)

func main() {
	flag.Parse()
	if len(*dbFile) == 0 {
		flag.Usage()
		return
	}

	conn, err := gorm.Open("sqlite3", *dbFile)
	if err != nil {
		fmt.Println("Failed to open db file:", err)
		return
	}
	defer conn.Close()

	var list db.CVEList
	stmt := conn.Debug().Model(&db.CVE{}).Where("status = 'fixed'")
	if *minScore > 0 {
		stmt = stmt.Where("score >= ?", *minScore)
	}
	if *maxScore > 0 {
		stmt = stmt.Where("score <= ?", *maxScore)
	}
	err = stmt.Order("package").Find(&list).Error
	if err != nil {
		fmt.Println("Failed to query:", err)
		return
	}

	fmt.Println("#+OPTIONS: toc:nil num:nil timstamp:nil ^:{} <:{}")
	fmt.Printf("#+TITLE: 需要更新的漏洞列表\n\n")

	fmt.Println("| Package | CVE | Patch | Description |")
	fmt.Println("|---------+-----+-------+-------------|")
	for _, info := range list {
		fmt.Printf("| %s | %s | %s | %s |\n", info.Package, info.ID, info.Patch, info.Description)
	}
}
