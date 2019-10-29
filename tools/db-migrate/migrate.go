package main

import (
	"flag"
	"fmt"

	"github.com/deepin-cve/tracker/pkg/db"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var (
	srcDB = flag.String("s", "", "the source db file")
	dstDB = flag.String("d", "", "the destination db file")
)

func main() {
	flag.Parse()

	if len(*srcDB) == 0 || len(*dstDB) == 0 {
		fmt.Println("Must special source and destination db file")
		return
	}

	src, err := gorm.Open("sqlite3", *srcDB)
	if err != nil {
		fmt.Println("Failed to open source db:", err)
		return
	}
	defer src.Close()

	dst, err := gorm.Open("sqlite3", *dstDB)
	if err != nil {
		fmt.Println("Failed to open destination db:", err)
		return
	}
	defer dst.Close()

	var (
		offset = 0
		limit  = 100
		length = 100
	)
	for length == limit {
		var list db.CVEList
		err := src.Model(&db.CVE{}).Offset(offset).Limit(limit).Find(&list).Error
		if err != nil {
			fmt.Println("Failed to query source db:", offset, limit, err)
			return
		}

		tx := dst.Begin()
		for _, info := range list {
			if info.Status == db.CVEStatusUnprocessed {
				continue
			}
			tx.Model(&db.CVE{}).Where("`id` = ?", info.ID).Updates(map[string]interface{}{
				"status":      info.Status,
				"patch":       info.Patch,
				"description": info.Description,
			})
		}
		err = tx.Commit().Error
		if err != nil {
			fmt.Println("Failed to commit description:", offset, limit, err)
			return
		}

		length = len(list)
		offset += length
	}

	return
}
