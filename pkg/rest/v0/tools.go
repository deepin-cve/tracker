package v0

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/deepin-cve/tracker/internal/config"
	"github.com/deepin-cve/tracker/pkg/db"
	"github.com/deepin-cve/tracker/pkg/fetcher"
	"github.com/deepin-cve/tracker/pkg/packages"
	"github.com/gin-gonic/gin"
)

const (
	nvdPrefix = "https://nvd.nist.gov/vuln/detail/"
)

func fetchDebian(c *gin.Context) {
	version := c.Param("version")
	if len(version) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid version",
		})
		return
	}
	var verInfo = db.Version{Version: version}
	err := verInfo.Get()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	var body = struct {
		Filters []string `json:"filters"`
	}{}
	err = c.ShouldBindJSON(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	infos, err := fetcher.Fetch(verInfo.ReleaseURL, body.Filters)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	go func(cveList db.DebianCVEList) {
		var list db.CVEList
		var scoreList db.CVEScoreList
		fmt.Println("Debian cve len:", len(cveList))
		for _, info := range cveList {
			if len(list) == 100 {
				err := list.Create(version)
				if err != nil {
					fmt.Println("Failed to create cve:", err)
					return
				}
				list = db.CVEList{}
			}
			var cve = db.CVE{
				DebianCVE:    *info,
				Status:       db.CVEStatusUnprocessed,
				PreInstalled: db.IsSourceExists(info.Package, version),
			}
			list = append(list, &cve)

			if len(scoreList) == 100 {
				err := scoreList.Create(version)
				if err != nil {
					fmt.Println("Failed to create cve score list")
					return
				}
				scoreList = db.CVEScoreList{}
			}
			score, err := fecthNVDScore(info.ID)
			if err != nil || score == nil {
				continue
			}
			scoreList = append(scoreList, score)
		}
		if len(list) != 0 {
			err := list.Create(version)
			if err != nil {
				fmt.Println("Failed to create cve:", err)
				return
			}
		}
		fmt.Println("Insert debian cve done:", body.Filters)
	}(infos)

	insertLog(&db.Log{
		Operator:    c.GetString("username"),
		Action:      db.LogActionFecthDebian,
		Description: strings.Join(body.Filters, ","),
	})

	c.String(http.StatusAccepted, "")
}

func initPackages(c *gin.Context) {
	version := c.Param("version")
	if len(version) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid version",
		})
		return
	}
	var verInfo = db.Version{Version: version}
	err := verInfo.Get()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	pkgHeader, err := c.FormFile("packages")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	var uploadFile = filepath.Join(config.GetConfig("").DBDir, "packages_"+version+"_"+string(db.GenToken()))
	err = c.SaveUploadedFile(pkgHeader, uploadFile)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	go func() {
		fmt.Println("Start to insert packages")
		err := packages.ImportPackage(uploadFile, version)
		if err != nil {
			fmt.Println("Failed to import packages:", err)
		}
		fmt.Println("Start to insert packages done")
	}()

	insertLog(&db.Log{
		Operator:    c.GetString("username"),
		Action:      db.LogActionInitPackage,
		Description: db.LogActionInitPackage.String(),
	})

	c.String(http.StatusAccepted, "")
}

func fetchScore(c *gin.Context) {
	version := c.Param("version")
	if len(version) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid version",
		})
		return
	}
	var verInfo = db.Version{Version: version}
	err := verInfo.Get()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	go func(v string) {
		fmt.Println("[Debug] start to fetch cve score")
		var (
			length = 100
			limit  = 100
			offset = 0

			scoreList = db.CVEScoreList{}

			handler = db.GetDBHandler(v)
		)
		for length == limit {
			if len(scoreList) >= 100 {
				err := scoreList.Create(v)
				if err != nil {
					fmt.Println("Failed to insert cve score:", err)
					return
				}
				scoreList = db.CVEScoreList{}
			}

			var cveList db.CVEList
			handler.Offset(offset).Limit(limit).Find(&cveList)
			length = len(cveList)
			offset += length

			for _, info := range cveList {
				var tmp = db.CVEScore{ID: info.ID}
				err := tmp.Get(v)
				if err == nil {
					continue
				}
				score, err := fecthNVDScore(info.ID)
				if err != nil || score == nil {
					continue
				}
				scoreList = append(scoreList, score)
			}
		}

		if len(scoreList) == 0 {
			return
		}
		err := scoreList.Create(v)
		if err != nil {
			fmt.Println("Failed to insert cve score:", err)
			return
		}
		fmt.Println("[Debug] fetch cve score done")
	}(version)

	insertLog(&db.Log{
		Operator:    c.GetString("username"),
		Action:      db.LogActionFetchScore,
		Description: db.LogActionFetchScore.String(),
	})

	c.String(http.StatusAccepted, "")
}

func fecthNVDScore(id string) (*db.CVEScore, error) {
	if !strings.Contains(id, "CVE") {
		return nil, nil
	}
	score, err := fetcher.FetchScore(nvdPrefix + id)
	if err != nil {
		fmt.Println("Failed to fetch cve score:", err, id)
		return nil, err
	}
	return score, nil
}
