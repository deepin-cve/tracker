package db

import (
	"fmt"
)

// Package store installed packages in ISO Image
type Package struct {
	Package       string `gorm:"primary_key"` // package + ':' + architecture, unique key
	Source        string
	Version       string
	Architecture  string
	SourceVersion string // if empty, equal with version
}

// PackageList package list
type PackageList []*Package

// NrePackage query package from db
func NewPackage(pkg, arch string) (*Package, error) {
	if len(pkg) == 0 || len(arch) == 0 {
		return nil, fmt.Errorf("invalid package(%q) or architecture(%q)",
			pkg, arch)
	}

	var info Package
	err := PkgDB.Where("`package` = ? AND `architecture` = ?",
		pkg, arch).First(&info).Error
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// IsSourceExists query whether source exists
func IsSourceExists(source string) bool {
	if len(source) == 0 {
		return false
	}

	var infos PackageList
	err := PkgDB.Model(&Package{}).Where("`source` = ?", source).Find(&infos).Error
	if err != nil {
		return false
	}
	if len(infos) == 0 {
		return false
	}
	return true
}

// Create insert package list
func (infos PackageList) Create() error {
	var tx = PkgDB.Begin()
	for _, info := range infos {
		err := tx.Model(&Package{}).Create(info).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}
