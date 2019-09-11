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
