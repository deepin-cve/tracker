package main

import (
	"fmt"

	"os"

	"github.com/deepin-cve/tracker/pkg/db"
)

// HuaweiCVE huawei cve db fields
type HuaweiCVE struct {
	ID      int     `json:"id"`
	Package string  `json:"package"`
	Version string  `json:"version"`
	CVE     string  `json:"cve"`
	CVSS    string  `json:"cvss"`
	Score   float64 `json:"score"`

	PreInstalled bool `json:"pre_installed"`

	DebianSource  string `json:"debian_source"`
	DebianVersion string `json:"debian_version"`
	DebianRelease string `json:"debian_release"`
	DebianStatus  string `json:"debian_status"`

	DeepinSource      string `json:"deepin_source"`
	DeepinVersion     string `json:"deepin_version"`
	DeepinStatus      string `json:"deepin_status"`
	DeepinPatch       string `json:"deepin_patch"`
	DeepinDescription string `json:"deepin_description"`
}

type HuaweiCVEList []*HuaweiCVE

func (list HuaweiCVEList) Len() int {
	return len(list)
}

func (list HuaweiCVEList) Swap(i, j int) {
	list[i], list[j] = list[j], list[i]
}

func (list HuaweiCVEList) Less(i, j int) bool {
	if list[i].Package == list[j].Package {
		return list[i].Score > list[i].Score
	}
	return list[i].Package < list[j].Package
}

func (list HuaweiCVEList) Create() error {
	tx := hwDB.Begin()
	for _, info := range list {
		err := tx.Model(&HuaweiCVE{}).Create(info).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}

func updateHuaweiDB() error {
	var (
		offset = 0
		length = 100
		limit  = 100
	)
	for length == limit {
		var infos HuaweiCVEList
		err := hwDB.Model(&HuaweiCVE{}).Offset(offset).Limit(limit).Find(&infos).Error
		if err != nil {
			fmt.Println("Failed to query huawei db:", offset, limit, err)
			return err
		}
		err = doUpdateHuaweiDB(infos)
		if err != nil {
			fmt.Println("Failed to update huawei db:", offset, limit, err)
			return err
		}

		length = len(infos)
		offset += length
	}
	return nil
}

func fetchHuaweiDB() error {
	var (
		offset = 0
		length = 100
		limit  = 100
	)
	for length == limit {
		var infos HuaweiCVEList
		err := hwDB.Model(&HuaweiCVE{}).Offset(offset).Limit(limit).Find(&infos).Error
		if err != nil {
			fmt.Println("Failed to query huawei db:", offset, limit, err)
			return err
		}

		tx := hwDB.Begin()
		for _, info := range infos {
			status, err := fetchIDStatus(info.CVE, *fetchRelease)
			if err != nil {
				fmt.Println("Failed to fetch id:", info.CVE, err)
				continue
			}
			err = tx.Model(&HuaweiCVE{}).Where("`id` = ?", info.ID).Updates(map[string]interface{}{
				"debian_source":  status.Package,
				"debian_version": status.Version,
				"debian_release": status.Release,
				"debian_status":  status.Status,
			}).Error
			if err != nil {
				tx.Rollback()
				fmt.Println("Failed to update huawei db:", err)
				return err
			}
		}
		tx.Commit()

		length = len(infos)
		offset += length
	}
	return nil
}

func exportCSVFile() error {
	fw, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Println("Failed to open file:", err)
		return err
	}
	defer fw.Close()

	fields := "Package,CVE,Version,CVSS,Score,PreInstalled"
	fields += ",DebianSource,DebianVersion,DebianRelease,DebianStatus"
	fields += ",DeepinSource,DeepinVersion,DeepinStatus,DeepinPatch,DeepinDescription"
	_, err = fw.WriteString(fields + "\n")
	if err != nil {
		fmt.Println("Failed to write fields:", err)
		return err
	}

	whereList := []string{
		fmt.Sprintf("`pre_installed` = 1 AND `score` >= 8"),
		fmt.Sprintf("`pre_installed` = 1 AND `score` < 8 AND `score` >= 7"),
		fmt.Sprintf("`pre_installed` = 1 AND `score` < 7"),
		fmt.Sprintf("`pre_installed` = 0 AND `score` >= 8"),
		fmt.Sprintf("`pre_installed` = 0 AND `score` < 8 AND `score` >= 7"),
		fmt.Sprintf("`pre_installed` = 0 AND `score` < 7"),
	}
	for _, where := range whereList {
		err = doExportCSVFile(fw, where)
		if err != nil {
			return err
		}
	}
	return fw.Sync()
}

func doExportCSVFile(fw *os.File, where string) error {
	var (
		offset = 0
		limit  = 100
		length = 100
	)
	for length == limit {
		var infos HuaweiCVEList
		err := hwDB.Model(&HuaweiCVE{}).Where(where).Offset(offset).Limit(limit).Find(&infos).Error
		if err != nil {
			fmt.Println("Failed to query huawei db:", where, err)
			return err
		}

		for _, info := range infos {
			ret := ""
			if info.DebianStatus == "fixed" {
				ret = "上游更新"
			} else if info.DeepinStatus == "fixed" {
				ret = "patch 修复"
			}
			if len(ret) != 0 {
				info.DeepinStatus = ret
			}

			_, _ = fw.WriteString(fmt.Sprintf("%s,%s,%s,%s,%v,%v,%s,%s,%s,%s,%s,%s,%s,%q,%q\n",
				info.Package, info.CVE, info.Version, info.CVSS, info.Score,
				info.PreInstalled, info.DebianSource, info.DebianVersion,
				info.DebianRelease, info.DebianStatus, info.DeepinSource,
				info.DeepinVersion, info.DeepinStatus, info.DeepinPatch,
				info.DeepinDescription))
		}

		length = len(infos)
		offset += length
	}
	return nil
}

func doUpdateHuaweiDB(infos HuaweiCVEList) error {
	hwTx := hwDB.Begin()
	for _, info := range infos {
		var cveInfo db.CVE
		err := cveDB.Model(&db.CVE{}).Where("`id` = ?", info.CVE).First(&cveInfo).Error
		if err == nil {
			info.DeepinStatus = cveInfo.Status
			info.DeepinPatch = cveInfo.Patch
			info.DeepinDescription = cveInfo.Description
		}
		var pkgInfo db.Package
		err = cveDB.Model(&db.Package{}).Where("`package` LIKE ? OR `source` = ?",
			fmt.Sprintf("%s:%", info.Package), info.Package).First(&pkgInfo).Error
		if err == nil {
			info.PreInstalled = true
			info.DeepinSource = pkgInfo.Source
			info.DeepinVersion = pkgInfo.Version
		}
		err = hwTx.Model(&HuaweiCVE{}).Where("`id` = ?", info.ID).Updates(info).Error
		if err != nil {
			hwTx.Rollback()
			return err
		}
	}
	return hwTx.Commit().Error
}
