package main

import (
	"flag"
	"fmt"

	"os"

	"bufio"
	"strconv"
	"strings"

	"github.com/deepin-cve/tracker/pkg/db"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var (
	csvFile      = flag.String("csv", "", "the huawei csv file")
	huaweiDBFile = flag.String("hw", "", "the huawei db file")
	cveDBFile    = flag.String("cve", "", "the cve db file")
	initHuawei   = flag.Bool("init", false, "init huawei db file")
	updateHuawei = flag.Bool("update", false, "update huawei db from cve db")
	fetchDebian  = flag.Bool("fetch", false, "fetch status from debian tracker")
	fetchRelease = flag.String("release", "", "the debian release for fetching")
	exportCSV    = flag.Bool("export", false, "export cvs file")
	outputFile   = flag.String("o", "", "the export filename")
	packageFile  = flag.String("pkg", "", "the updated package list file")
	initPackage  = flag.Bool("initPkg", false, "init package list db")

	hwDB  *gorm.DB = nil
	cveDB *gorm.DB = nil
)

func main() {
	flag.Parse()

	// test cve fetch
	// tmp, err1 := fetchIDStatus("CVE-2017-5130", *fetchRelease)
	// if err1 != nil {
	// 	fmt.Println("Failed to fetch:", err1)
	// } else {
	// 	fmt.Printf("Info: %q, %q, %q, %q, %q\n", tmp.ID, tmp.Package, tmp.Version,
	// 		tmp.Release, tmp.Status)
	// }
	// return

	if len(*csvFile) == 0 && len(*huaweiDBFile) == 0 && len(*cveDBFile) == 0 {
		fmt.Printf("No file given!\n\n")
		flag.Usage()
		return
	}

	err := connectDB()
	if err != nil {
		fmt.Println("Failed to connect db:", err)
		return
	}
	defer func() {
		if hwDB != nil {
			_ = hwDB.Close()
		}
		if cveDB != nil {
			_ = cveDB.Close()
		}
	}()

	if *initHuawei {
		if len(*csvFile) == 0 || len(*huaweiDBFile) == 0 {
			fmt.Println("Must special the csv file and huawei db file")
			return
		}
		err := initHuaweiDB()
		if err != nil {
			fmt.Println("Failed to init huawei db:", err)
			return
		}
	}

	if *updateHuawei {
		if len(*huaweiDBFile) == 0 || len(*cveDBFile) == 0 {
			fmt.Println("Must speical the huawei db file and cve db file")
			return
		}
		err := updateHuaweiDB()
		if err != nil {
			return
		}
	}

	if *fetchDebian {
		if len(*huaweiDBFile) == 0 || len(*fetchRelease) == 0 {
			fmt.Println("Must special the huawei db file and debian release")
			return
		}
		err := fetchHuaweiDB()
		if err != nil {
			return
		}
	}

	if *exportCSV {
		if len(*huaweiDBFile) == 0 || len(*outputFile) == 0 {
			fmt.Println("Must special the huawei db file and output filename")
			return
		}
		err := exportCSVFile()
		if err != nil {
			return
		}
	}

	if *initPackage {
		if len(*packageFile) == 0 || len(*huaweiDBFile) == 0 {
			fmt.Println("Must special the package list file and db file")
			return
		}
		err := initHuaweiPackage()
		if err != nil {
			return
		}
		err = updateDeepinVersion()
		if err != nil {
			return
		}
	}
}

func connectDB() error {
	var err error
	if len(*huaweiDBFile) != 0 {
		hwDB, err = gorm.Open("sqlite3", *huaweiDBFile)
		if err != nil {
			return err
		}
		hwDB.AutoMigrate(&HuaweiCVE{})
		hwDB.AutoMigrate(&db.Package{})
	}
	if len(*cveDBFile) != 0 {
		cveDB, err = gorm.Open("sqlite3", *cveDBFile)
		if err != nil {
			return err
		}
	}
	return nil
}

func initHuaweiDB() error {
	// csv format: package, version, cve, csvs, score
	fr, err := os.Open(*csvFile)
	if err != nil {
		return err
	}
	defer fr.Close()

	// clear table rows
	err = hwDB.Delete(&HuaweiCVE{}).Error
	if err != nil {
		return err
	}

	var infos HuaweiCVEList
	var scanner = bufio.NewScanner(fr)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		items := strings.Split(line, ",")
		if len(items) != 5 {
			fmt.Println("Invalid csv format:", line)
			continue
		}

		if len(infos) == 100 {
			err := infos.Create()
			if err != nil {
				fmt.Println("Failed to create huawei rows:", err)
				return err
			}
			infos = HuaweiCVEList{}
		}

		infos = append(infos, &HuaweiCVE{
			Package: correctPackageName(items[0]),
			Version: items[1],
			CVE:     items[2],
			CVSS:    items[3],
			Score:   strToFloat64(items[4]),
		})
	}

	if len(infos) == 0 {
		return nil
	}
	err = infos.Create()
	if err != nil {
		fmt.Println("Failed to create huawei rows:", err)
	}
	return err
}

func hwCreatePackages(list db.PackageList) error {
	tx := hwDB.Begin()
	for _, info := range list {
		err := tx.Create(info).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}

func initHuaweiPackage() error {
	// csv format: package, architecture, version, source
	fr, err := os.Open(*packageFile)
	if err != nil {
		return err
	}
	defer fr.Close()

	// clear table rows
	err = hwDB.Delete(&db.Package{}).Error
	if err != nil {
		return err
	}

	var infos db.PackageList
	var scanner = bufio.NewScanner(fr)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		items := strings.Split(line, ",")
		if len(items) != 4 {
			fmt.Println("Invalid csv format:", line)
			continue
		}

		if len(infos) == 100 {
			err := hwCreatePackages(infos)
			if err != nil {
				fmt.Println("Failed to create huawei package rows:", err)
				return err
			}
			infos = db.PackageList{}
		}

		info := &db.Package{
			Package:      fmt.Sprintf("%s:%s", items[0], items[1]),
			Architecture: items[1],
			Version:      items[2],
			Source:       items[2],
		}
		// source version
		tmp := strings.Split(info.Source, " (")
		if len(tmp) != 2 {
			info.SourceVersion = info.Version
		} else {
			info.Source = tmp[0]
			info.SourceVersion = tmp[1]
		}

		infos = append(infos, info)
	}

	if len(infos) == 0 {
		return nil
	}
	err = hwCreatePackages(infos)
	if err != nil {
		fmt.Println("Failed to create huawei package rows:", err)
	}
	return err
}

func updateDeepinVersion() error {
	var (
		offset = 0
		length = 100
		limit  = 100
	)
	for length == limit {
		var infos HuaweiCVEList
		err := hwDB.Model(&HuaweiCVE{}).Offset(offset).Limit(limit).Find(&infos).Error
		if err != nil {
			return err
		}

		tx := hwDB.Begin()
		for _, info := range infos {
			var pkgInfo db.Package
			err = tx.Model(&db.Package{}).Where("`package` LIKE ? OR `source` = ?",
				fmt.Sprintf("%s:%", info.Package),
				info.Package).First(&pkgInfo).Error
			if err != nil {
				continue
			}
			if info.DeepinVersion == pkgInfo.Version {
				continue
			}
			err = tx.Model(&HuaweiCVE{}).Where("`id` = ?",
				info.ID).Update("deepin_version", pkgInfo.Version).Error
			if err != nil {
				tx.Rollback()
				fmt.Println("Failed to update deepin version:",
					info.Package, pkgInfo.Package, pkgInfo.Version)
				return err
			}
		}
		tx.Commit()

		length = len(infos)
		offset += length
	}

	return nil
}

func fetchDebianStatus() error {
	return nil
}

func correctPackageName(s string) string {
	switch s {
	case "linux_kernel":
		return "linux"
	default:
		return s
	}
}

func strToFloat64(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}
