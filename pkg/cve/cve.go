package cve

import (
	"fmt"

	"github.com/deepin-cve/tracker/pkg/db"
	"github.com/jinzhu/gorm"
)

// QueryCVEList query by filter
// TODO(jouyouyun): add scope filter supported
func QueryCVEList(params map[string]interface{}, filterList []string,
	offset, count int) (db.CVEList, int64, error) {
	var sql = db.CVEDB.Model(&db.CVE{})

	addParamsToSQL(sql, params)
	if len(filterList) != 0 {
		sql = sql.Where("`urgency` = ?", filterList[0])
		for i := 1; i < len(filterList); i++ {
			sql = sql.Or("`urgency` = ?", filterList[i])
		}
	}

	var list db.CVEList
	var total int64
	err := sql.Count(&total).Offset(offset).Limit(count).Find(&list).Error
	if err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

// UpdateCVE modify cve info
func UpdateCVE(id string, values map[string]interface{}) (*db.CVE, error) {
	cve, err := db.NewCVE(id)
	if err != nil {
		return nil, err
	}

	err = db.CVEDB.Model(cve).Updates(values).Error
	if err != nil {
		return nil, err
	}
	return cve, nil
}

func addParamsToSQL(sql *gorm.DB, params map[string]interface{}) {
	if len(params) == 0 {
		return
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
}
