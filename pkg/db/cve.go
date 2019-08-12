package db

import (
	"fmt"
	"time"
)

const (
	// CVE status available values
	CVEStatusUnprocessed = "unprocessed"
	CVEStatusProcessing  = "processing"
	CVEStatusCanceled    = "canceled"
	CVEStatusFinished    = "finished"
)

// DebianCVE store cve bug from debian tracker
type DebianCVE struct {
	ID      string `gorm:"primary_key"`
	Package string
	Urgency string
	Remote  string
}

// DebianCVEList an array for CVE
type DebianCVEList []*DebianCVE

// CVE store cve bug for tracking
type CVE struct {
	DebianCVE
	Status      string
	Patch       string
	Description string

	PreInstalled bool
	Archived     bool

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// CVEList an array for CVE
type CVEList []*CVE

// FixPackage fill package
func (list DebianCVEList) FixPackage() {
	var prev string
	for _, cve := range list {
		if len(cve.Package) != 0 {
			prev = cve.Package
		} else {
			cve.Package = prev
		}
	}
}

func (list DebianCVEList) Dump() {
	fmt.Println("\n--------- DUMP --------")
	for _, cve := range list {
		fmt.Println(cve.Package, cve.ID, cve.Urgency, cve.Remote)
	}
	fmt.Println("--------- DUMP END --------")
}

// Create insert cve record, if exists, ignore
func (list CVEList) Create() error {
	var tx = CVEDB.Begin()

	for _, cve := range list {
		var info CVE
		tx.Where("`id` = ?", cve.ID).First(&info)
		if info.ID == cve.ID {
			// exists
			continue
		}
		err := tx.Create(cve).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}

// Save save cve info
func (cve *CVE) Save() error {
	return CVEDB.Save(cve).Error
}

// NewCVE query cve by id
func NewCVE(id string) (*CVE, error) {
	var cve CVE
	err := CVEDB.Where("`id` = ?", id).First(&cve).Error
	if err != nil {
		return nil, err
	}
	return &cve, nil
}

// UpdateCVE update cve info with values
func UpdateCVE(diff map[string]interface{}) error {
	return CVEDB.Model(&CVE{}).Updates(diff).Error
}
