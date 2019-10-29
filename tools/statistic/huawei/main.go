package main

import (
	"flag"
	"fmt"

	"os"

	"bufio"
	"strconv"
	"strings"

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
}

func connectDB() error {
	var err error
	if len(*huaweiDBFile) != 0 {
		hwDB, err = gorm.Open("sqlite3", *huaweiDBFile)
		if err != nil {
			return err
		}
		hwDB.AutoMigrate(&HuaweiCVE{})
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
