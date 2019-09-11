package db

import (
	"path/filepath"

	"sync"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var (
	// CommonDB session, version, log db handler
	CommonDB *gorm.DB

	cveDBSet     = make(map[string]*gorm.DB)
	cveSetLocker sync.Mutex

	_dbDir string
)

// Init init db
func Init(dbDir string) {
	_dbDir = dbDir
	var err error
	CommonDB, err = gorm.Open("sqlite3", filepath.Join(dbDir, "common.db"))
	if err != nil {
		panic(err)
	}

	CommonDB.AutoMigrate(&Session{})
	CommonDB.AutoMigrate(&Version{})
	CommonDB.AutoMigrate(&Log{})
	// TODO(jouyouyun): add to configuration
	CommonDB.DB().SetMaxIdleConns(10)
	CommonDB.DB().SetMaxOpenConns(100)

	var verList VersionList
	err = CommonDB.Find(&verList).Error
	if err != nil {
		panic(err)
	}

	for _, ver := range verList {
		err = doSetDBHandler(ver.Version)
		if err != nil {
			panic(err)
		}
	}
}

// GetDBHandler return db handler by version
func GetDBHandler(version string) *gorm.DB {
	handler, ok := cveDBSet[version]
	if !ok {
		return nil
	}
	return handler
}

// SetDBHandler init db handler
func SetDBHander(version string) error {
	cveSetLocker.Lock()
	defer cveSetLocker.Unlock()

	if handler, ok := cveDBSet[version]; ok && handler != nil {
		return nil
	}
	return doSetDBHandler(version)
}

// DeleteDBHandler delete db handler
func DeleteDBHandler(version string) error {
	cveSetLocker.Lock()
	defer cveSetLocker.Unlock()

	handler, ok := cveDBSet[version]
	delete(cveDBSet, version)
	if !ok || handler == nil {
		return nil
	}
	return handler.Close()
}

func doSetDBHandler(version string) error {
	db, err := gorm.Open("sqlite3", filepath.Join(_dbDir, version+".db"))
	if err != nil {
		return err
	}
	db.AutoMigrate(&CVE{})
	db.AutoMigrate(&Package{})
	// TODO(jouyouyun): add to configuration
	db.DB().SetMaxIdleConns(10)
	db.DB().SetMaxOpenConns(100)
	cveDBSet[version] = db
	return nil
}
