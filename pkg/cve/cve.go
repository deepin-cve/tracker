package cve

import (
	"fmt"

	"github.com/deepin-cve/tracker/pkg/db"
	"github.com/jinzhu/gorm"
)

// QueryCVEList query by filter
// TODO(jouyouyun): add scope filter supported
func QueryCVEList(params map[string]interface{}, offset, count int,
	version string) (db.CVEList, int64, error) {
	handler := db.GetDBHandler(version)
	if handler == nil {
		return nil, 0, fmt.Errorf("No db handler found for version '%s'", version)
	}

	var sql = handler.Model(&db.CVE{})
	sql = addParamsToSQL(sql, params)
	value, ok := params["sort"]
	if ok {
		sort, ok := value.(string)
		if ok && len(sort) != 0 {
			var order string
			if sort == "updated_at" {
				order = " desc"
			}
			sql = sql.Order(fmt.Sprintf("%s%s", sort, order))
		}
	}

	var list db.CVEList
	var total int64
	err := sql.Count(&total).Offset(offset).Limit(count).Find(&list).Error
	if err != nil {
		return nil, 0, err
	}

	for _, info := range list {
		handler.Model(info).Related(&info.Score, "ID").First(&info.Score)
	}
	return list, total, nil
}

// UpdateCVE modify cve info
func UpdateCVE(id, version string, values map[string]interface{}) (*db.CVE, error) {
	cve, err := db.NewCVE(id, version)
	if err != nil {
		return nil, err
	}

	err = cve.Update(values, version)
	if err != nil {
		return nil, err
	}
	return cve, nil
}

func addParamsToSQL(sql *gorm.DB, params map[string]interface{}) *gorm.DB {
	if len(params) == 0 {
		return sql
	}

	var availableList = []struct {
		key     string
		useLike bool
	}{
		{"package", true},
		{"pre_installed", false},
		{"archived", false},
		{"remote", false},
	}

	for _, item := range availableList {
		if v, ok := params[item.key]; ok {
			compare := "="
			if item.useLike {
				compare = "LIKE"
			}
			sql = sql.Where(fmt.Sprintf("`%s` %s ?", item.key, compare),
				v)
		}
	}
	return addListParamsToSQL(sql, params)
}

func addListParamsToSQL(sql *gorm.DB, params map[string]interface{}) *gorm.DB {
	var availableList = []struct {
		key    string
		column string
	}{
		{"status", "status"},
		{"filters", "urgency"},
	}
	for _, info := range availableList {
		values, ok := params[info.key]
		if !ok {
			continue
		}
		list, ok := values.([]string)
		if !ok {
			continue
		}
		if len(list) != 0 {
			col := fmt.Sprintf("`%s` = ?", info.column)
			sql = sql.Where(col, list[0])
			for i := 1; i < len(list); i++ {
				sql = sql.Or(col, list[i])
			}
		}
	}
	return sql
}
