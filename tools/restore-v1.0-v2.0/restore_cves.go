package main

import (
	"flag"
	"fmt"

	"github.com/deepin-cve/tracker/pkg/db"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var (
	srcDBFile = flag.String("s", "", "the source cves db file")
	dstDBFile = flag.String("d", "", "the destination cves db file")
)

func main() {
	flag.Parse()

	if len(*srcDBFile) == 0 || len(*dstDBFile) == 0 {
		flag.Usage()
		return
	}

	src, err := gorm.Open("sqlite3", *srcDBFile)
	if err != nil {
		fmt.Println("Failed to open sqlite3:", err)
		return
	}
	defer src.Close()
	dst, err := gorm.Open("sqlite3", *dstDBFile)
	if err != nil {
		fmt.Println("Failed to open sqlite3:", err)
		return
	}
	defer dst.Close()

	var offset = 0
	var limit = 100
	var length = 100
	for length == limit {
		var list db.CVEList
		err := src.Offset(offset).Limit(limit).Find(&list).Error
		if err != nil {
			fmt.Println("Failed to query cves:", err)
			return
		}

		length = len(list)
		offset += length

		err = importRecords(dst, list)
		if err != nil {
			fmt.Println("Failed to query cves:", err)
			return
		}
	}
}

func importRecords(dst *gorm.DB, list db.CVEList) error {
	tx := dst.Begin()
	for _, info := range list {
		err := tx.Create(info).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}
