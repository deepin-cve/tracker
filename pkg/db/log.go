package db

import (
	"fmt"
	"sort"
)

// ActionType action types
type ActionType int

// Log operation records
type Log struct {
	ID          int        `gorm:"auto_increment;primary_key" json:"id"`
	Operator    string     `json:"operator"`
	Action      ActionType `json:"action"`
	ActionDesc  string     `gorm:"-" json:"action_desc"`
	Target      string     `json:"target"`
	Description string     `json:"description"`
}

// LogList log list
type LogList []*Log

const (
	LogActionInitPackage ActionType = iota + 1
	LogActionFecthDebian
	LogActionPatchCVE
	LogActionLogin
	LogActionLogout
	LogActionNewVersion
	LogActionPatchVersion
	LogActionDeleteVersion
	LogActionFetchScore
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
	case LogActionNewVersion:
		return "Create version"
	case LogActionPatchVersion:
		return "Modify version"
	case LogActionDeleteVersion:
		return "Delete version"
	case LogActionFetchScore:
		return "Fetch score"
	}
	return fmt.Sprint(action)
}

func (list LogList) Len() int {
	return len(list)
}

func (list LogList) Less(i, j int) bool {
	return list[i].ID > list[j].ID
}

func (list LogList) Swap(i, j int) {
	list[i], list[j] = list[j], list[i]
}

func (list LogList) fix() {
	for _, info := range list {
		info.ActionDesc = info.Action.String()
	}
}

// Create insert log
func (l *Log) Create() error {
	return CommonDB.Create(l).Error
}

// QueryLogList query log list, available params: operator, target
func QueryLogList(params map[string]string) (LogList, error) {
	// TODO(jouyouyun): add offset, limit

	var sql = CommonDB.Model(&Log{})
	if v, ok := params["operator"]; ok {
		sql = sql.Where("`operator` = ?", v)
	}
	if v, ok := params["target"]; ok {
		sql = sql.Where("`target` = ?", v)
	}

	var list LogList
	err := sql.Find(&list).Error
	if err != nil {
		return nil, err
	}

	list.fix()
	sort.Sort(list)
	return list, nil
}
