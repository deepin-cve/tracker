package main

import (
	"flag"
	"fmt"

	"github.com/deepin-cve/tracker/pkg/db"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var (
	start = flag.String("s", "", "the start time, as: '2019-09-16 00:00:00'")
	end   = flag.String("e", "", "the start time, as: '2019-09-17 00:00:00'")

	dbFile = flag.String("db", "", "the db file")

	dbConn *gorm.DB
)

func main() {
	flag.Parse()

	if len(*dbFile) == 0 {
		fmt.Println("Must special db file")
		return
	}

	var err error
	dbConn, err = gorm.Open("sqlite3", *dbFile)
	if err != nil {
		fmt.Println("Failed to open db file:", err)
		return
	}
	defer dbConn.Close()

	fmt.Println("#+OPTIONS: toc:nil num:nil timestamp:nil ^:{} <:{}")
	var title string
	if len(*start) != 0 {
		title += *start
	}
	if len(*end) != 0 {
		title += " 至 " + *end
	} else {
		title += " 至今"
	}
	fmt.Printf("#+TITLE: %s的 CVE 处理情况\n\n", title)

	fmt.Printf("+ 已修复的\n\n")
	fmt.Println("| Package | CVE | Patch | Description |")
	fmt.Println("|---------+-----+-------+-------------|")
	err = exportCVEList("fixed")
	if err != nil {
		fmt.Println("Failed to export fixed:", err)
		return
	}

	fmt.Printf("+ 已延后的\n\n")
	fmt.Println("| Package | CVE | Patch | Description |")
	fmt.Println("|---------+-----+-------+-------------|")
	err = exportCVEList("postpone")
	if err != nil {
		fmt.Println("Failed to export postpone:", err)
		return
	}

	fmt.Printf("+ 已搁置的\n\n")
	fmt.Println("| Package | CVE | Patch | Description |")
	fmt.Println("|---------+-----+-------+-------------|")
	err = exportCVEList("hold")
	if err != nil {
		fmt.Println("Failed to export hold:", err)
		return
	}

	fmt.Printf("+ 已取消的\n\n")
	fmt.Println("| Package | CVE | Patch | Description |")
	fmt.Println("|---------+-----+-------+-------------|")
	err = exportCVEList("cancel")
	if err != nil {
		fmt.Println("Failed to export cancel:", err)
		return
	}
}

func exportCVEList(status string) error {
	var list db.CVEList
	var handler = dbConn.Model(&db.CVE{})
	if len(*start) != 0 {
		handler = handler.Where("`updated_at` > ?", *start)
	}
	if len(*end) != 0 {
		handler = handler.Where("`updated_at` < ?", *end)
	}

	err := handler.Where("`status` = ?", status).Find(&list).Error
	if err != nil {
		return err
	}

	for _, info := range list {
		fmt.Printf("| %s | https://security-tracker.debian.org/tracker/%s | %s | %s |\n",
			info.Package, info.ID, info.Patch, info.Description)
	}
	fmt.Printf("\n\n")

	return nil
}
