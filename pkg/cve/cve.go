package cve

import (
	"github.com/jouyouyun/deepin-cve-tracker/pkg/db"
)

// QueryCVEList query by filter
// TODO(jouyouyun): add scope filter supported
func QueryCVEList(pkg string, filterList []string, offset, count int) (db.CVEList, int64, error) {
	var sql = db.CVEDB.Model(&db.CVE{})
	if len(pkg) != 0 {
		sql = sql.Where("`package` LIKE '%?%'", pkg)
	}
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
