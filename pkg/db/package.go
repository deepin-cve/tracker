package db

import (
	"fmt"
)

// Package store installed packages in ISO Image
type Package struct {
	Package       string `gorm:"primary_key" json:"package"` // package + ':' + architecture, unique key
	Source        string `json:"source"`
	Version       string `json:"version"`
	Architecture  string `json"architecture`
	SourceVersion string `json:"source_version"` // if empty, equal with version
}

// PackageList package list
type PackageList []*Package

// NrePackage query package from db
func NewPackage(pkg, arch, dbVersion string) (*Package, error) {
	if len(pkg) == 0 || len(arch) == 0 {
		return nil, fmt.Errorf("invalid package(%q) or architecture(%q)",
			pkg, arch)
	}

	handler := GetDBHandler(dbVersion)
	if handler == nil {
		return nil, fmt.Errorf("Not found db hander for version '%s'", dbVersion)
	}

	var info Package
	err := handler.Where("`package` = ? AND `architecture` = ?",
		pkg, arch).First(&info).Error
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// IsSourceExists query whether source exists
func IsSourceExists(source, dbVersion string) bool {
	if len(source) == 0 {
		return false
	}

	handler := GetDBHandler(dbVersion)
	if handler == nil {
		return false
	}

	var infos PackageList
	err := handler.Model(&Package{}).Where("`source` = ?", source).Find(&infos).Error
	if err != nil {
		return false
	}
	if len(infos) == 0 {
		return false
	}
	return true
}

// Create insert package list
func (infos PackageList) Create(dbVersion string) error {
	handler := GetDBHandler(dbVersion)
	if handler == nil {
		return fmt.Errorf("Not found db hander for version '%s'", dbVersion)
	}

	var tx = handler.Begin()
	for _, info := range infos {
		err := tx.Model(&Package{}).Create(info).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}
