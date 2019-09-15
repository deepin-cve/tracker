package db

import (
	"fmt"
	"strings"
	"time"
)

const (
	// CVE status available values
	CVEStatusUnprocessed = "unprocessed" // 未处理
	CVEStatusProcessing  = "processing"  // 处理中
	CVEStatusPostpone    = "postpone"    // 延后
	CVEStatusHold        = "hold"        // 搁置
	CVEStatusCanceled    = "canceled"    // 取消
	CVEStatusFixed       = "fixed"       // 完成
)

// Filter urgency level
type FilterUrgency string

const (
	// Filter tracker filter
	FilterUrgencyHigh           FilterUrgency = "high_urgency"
	FilterUrgencyMedium                       = "medium_urgency"
	FilterUrgencyLow                          = "low_urgency"
	FilterUrgencyUnimportant                  = "unimportant_urgency"
	FilterUrgencyNotYetAssigned               = "unassigned_urgency"
	FilterUrgencyEndOfLife                    = "endoflife_urgency"
)

func (filter FilterUrgency) String() string {
	var ret string
	switch filter {
	case FilterUrgencyHigh:
		ret = "high"
	case FilterUrgencyMedium:
		ret = "medium"
	case FilterUrgencyLow:
		ret = "low"
	case FilterUrgencyUnimportant:
		ret = "unimportant"
	case FilterUrgencyNotYetAssigned:
		ret = "not yet assigned"
	case FilterUrgencyEndOfLife:
		ret = "end of life"
	default:
		ret = "unknown"
	}
	return ret
}

// Filter scope
type FilterScope string

const (
	// Filter scope list
	FilterScopeHideRemote   FilterScope = "remote"
	FilterScopeHideLocal                = "locale"
	FilterScopeHideUnclear              = "unclear"
	FilterScopeUndetermined             = "undetermined_issues"
	FilterScopeNoDSA                    = "nodsa"
	FilterScopeIgnore                   = "noignored"
	FilterScopePostponed                = "nopostponed"
)

func (filter FilterScope) String() string {
	var ret string
	switch filter {
	case FilterScopeHideRemote:
		ret = "hide remote"
	case FilterScopeHideLocal:
		ret = "hide local"
	case FilterScopeHideUnclear:
		ret = "hide unclear"
	case FilterScopeUndetermined:
		ret = "include issues to be checked"
	case FilterScopeNoDSA:
		ret = "include issues tagged <on-dsa>"
	case FilterScopeIgnore:
		ret = "include issues tagged <no-ignored>"
	case FilterScopePostponed:
		ret = "include issues tagged <postponed>"
	default:
		ret = "unknown"
	}
	return ret
}

// DebianCVE store cve bug from debian tracker
type DebianCVE struct {
	ID      string `gorm:"primary_key" json:"id"`
	Package string `json:"package"`
	Urgency string `json:"urgency"`
	Remote  string `json:"remote"`
}

// DebianCVEList an array for CVE
type DebianCVEList []*DebianCVE

// FixUrgency correct urgency
func (info *DebianCVE) FixUrgency() {
	switch {
	case strings.HasPrefix(info.Urgency, "high"):
		info.Urgency = string(FilterUrgencyHigh)
	case strings.HasPrefix(info.Urgency, "medium"):
		info.Urgency = string(FilterUrgencyMedium)
	case strings.HasPrefix(info.Urgency, "low"):
		info.Urgency = string(FilterUrgencyLow)
	case strings.HasPrefix(info.Urgency, "unimportant"):
		info.Urgency = string(FilterUrgencyUnimportant)
	case strings.HasPrefix(info.Urgency, "not yet assigned"):
		info.Urgency = string(FilterUrgencyNotYetAssigned)
	case strings.HasPrefix(info.Urgency, "end-of-life"):
		info.Urgency = string(FilterUrgencyEndOfLife)
	}
}

// CVE store cve bug for tracking
type CVE struct {
	DebianCVE
	Status      string `json:"status"`
	Patch       string `json:"patch"`
	Description string `json:"description"`

	PreInstalled bool `json:"pre_installed"`
	Archived     bool `json:"archived"`

	Score CVEScore `gorm:"FOREIGNKEY:ID;ASSOCIATION_FOREIGNKEY:ID" json:"score"`

	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"-"`
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
func (list CVEList) Create(version string) error {
	handler := GetDBHandler(version)
	if handler == nil {
		return fmt.Errorf("Not found db hander for version '%s'", version)
	}
	var tx = handler.Begin()

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
func (cve *CVE) Save(version string) error {
	handler := GetDBHandler(version)
	if handler == nil {
		return fmt.Errorf("Not found db hander for version '%s'", version)
	}
	return handler.Save(cve).Error
}

// NewCVE query cve by id
func NewCVE(id, version string) (*CVE, error) {
	handler := GetDBHandler(version)
	if handler == nil {
		return nil, fmt.Errorf("Not found db hander for version '%s'", version)
	}

	var cve CVE
	err := handler.Preload("Score").Where("`id` = ?", id).First(&cve).Error
	if err != nil {
		return nil, err
	}
	return &cve, nil
}

// UpdateCVE update cve info with values
func (cve *CVE) Update(diff map[string]interface{}, version string) error {
	handler := GetDBHandler(version)
	if handler == nil {
		return fmt.Errorf("Not found db hander for version '%s'", version)
	}
	return handler.Model(cve).Updates(diff).Error
}

// ValidStatus validity status whether right
func ValidStatus(status string) bool {
	switch status {
	case CVEStatusUnprocessed, CVEStatusProcessing, CVEStatusPostpone, CVEStatusHold,
		CVEStatusFixed, CVEStatusCanceled:
		return true
	}
	return false
}

// ValidColumn validity cve table whether has this column name
func ValidColumn(name string) bool {
	switch name {
	case "id", "package", "urgency", "remote", "status", "patch", "description",
		"pre_installed", "archived", "created_at", "updated_at":
		return true
	}
	return false
}
