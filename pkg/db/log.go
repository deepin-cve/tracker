package db

import (
	"fmt"
)

// ActionType action types
type ActionType int

// Log operation records
type Log struct {
	ID          int        `gorm:"auto_increment;primary_key" json:"id"`
	Operator    string     `json:"operator"`
	Action      ActionType `json:"action"`
	ActionDesc  string     `gorm:"-" json:"action_desc"`
	Description string     `json:"description"`
}

const (
	LogActionInitPackage ActionType = iota + 1
	LogActionFecthDebian
	LogActionPatchCVE
	LogActionLogin
	LogActionLogout
)

// String action description
func (action ActionType) String() string {
	switch action {
	case LogActionInitPackage:
		return "Init package"
	case LogActionFecthDebian:
		return "Import debian cve"
	case LogActionPatchCVE:
		return "Modify cve"
	case LogActionLogin:
		return "Login"
	case LogActionLogout:
		return "Logout"
	}
	return fmt.Sprint(action)
}

// Create insert log
func (l *Log) Create() error {
	return LogDB.Create(l).Error
}
