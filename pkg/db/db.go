package db

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var (
	// PkgDB packages db handler
	PkgDB *gorm.DB
	// CVEDB cve db handler
	CVEDB *gorm.DB
)

// Init init db
func Init(repo, cve string) {
	var err error
	PkgDB, err = gorm.Open("sqlite3", repo)
	if err != nil {
		panic(err)
	}
	// TODO(jouyouyun): add to configuration
	PkgDB.DB().SetMaxIdleConns(10)
	PkgDB.DB().SetMaxOpenConns(100)

	CVEDB, err = gorm.Open("sqlite3", cve)
	if err != nil {
		panic(err)
	}
	// TODO(jouyouyun): add to configuration
	CVEDB.DB().SetMaxIdleConns(10)
	CVEDB.DB().SetMaxOpenConns(100)

	PkgDB.AutoMigrate(&Package{})
	CVEDB.AutoMigrate(&CVE{})
}
