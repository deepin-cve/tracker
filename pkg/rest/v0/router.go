package v0

import (
	"fmt"

	"strconv"

	"strings"

	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jouyouyun/deepin-cve-tracker/internal/config"
	"github.com/jouyouyun/deepin-cve-tracker/pkg/cve"
	"github.com/jouyouyun/deepin-cve-tracker/pkg/db"
	"github.com/jouyouyun/deepin-cve-tracker/pkg/fetcher"
	"github.com/jouyouyun/deepin-cve-tracker/pkg/packages"
)

const (
	defaultPageCount = 15
)

// Route start gin router
func Route(addr string, debug bool) error {
	if debug {
		gin.SetMode(gin.DebugMode)
	}
	var eng = gin.Default()

	// TODO(jouyouyun): add session authority
	v0 := eng.Group("v0")

	cve := v0.Group("cve")
	cve.GET("", getCVEList)
	cve.GET("/:id", getCVE)
	cve.PATCH("/:id", patchCVE)

	tools := v0.Group("tools")
	tools.POST("/cve/fetch", fetchCVE)
	tools.POST("/packages", initPackages)

	return eng.Run(addr)
}

func getCVEList(c *gin.Context) {
	// query parameters: name, filters(only urgency), page, count
	// filters split by ','
	var flist []string
	pageStr := c.DefaultQuery("page", "1")
	page, _ := strconv.Atoi(pageStr)
	countStr := c.DefaultQuery("count", fmt.Sprint(defaultPageCount))
	count, _ := strconv.Atoi(countStr)
	filters := c.Query("filters")
	if len(filters) != 0 {
		flist = strings.Split(filters, ",")
	}

	infos, total, err := cve.QueryCVEList(c.Query("package"), flist, (page-1)*count, count)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.Header("X-Resource-Page", fmt.Sprint(page))
	c.Header("X-Resource-Total", fmt.Sprint(total))
	c.Header("X-Resource-Count", fmt.Sprint(count))
	c.JSON(http.StatusOK, infos)
}

func getCVE(c *gin.Context) {
	id := c.Param("id")
	info, err := db.NewCVE(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, info)
}

func patchCVE(c *gin.Context) {
	id := c.Param("id")
	var values = make(map[string]interface{})
	err := c.Bind(values)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	info, err := cve.UpdateCVE(id, values)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, info)
}

func fetchCVE(c *gin.Context) {
	// query parameters: filters(urgency and scope)
	// filters split by ','
	var flist []string
	filters := c.Query("filters")
	if len(filters) != 0 {
		flist = strings.Split(filters, ",")
	}
	infos, err := fetcher.Fetch(config.GetConfig("").DebianTracker.HomeURL, flist)
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
				err := list.Create()
				if err != nil {
					fmt.Println("Failed to create cve:", err)
					return
				}
				list = db.CVEList{}
			}
			var cve = db.CVE{
				DebianCVE:    *info,
				Status:       db.CVEStatusUnprocessed,
				PreInstalled: db.IsSourceExists(info.Package),
			}
			list = append(list, &cve)
		}
		if len(list) != 0 {
			err := list.Create()
			if err != nil {
				fmt.Println("Failed to create cve:", err)
				return
			}
		}
		fmt.Println("Insert debian cve done:", filters)
	}(infos)
	c.String(http.StatusAccepted, "")
}

func initPackages(c *gin.Context) {
	go func() {
		fmt.Println("Start to insert packages")
		err := packages.ImportPackage(config.GetConfig("").PackagesFile)
		if err != nil {
			fmt.Println("Failed to import packages:", err)
		}
		fmt.Println("Start to insert packages done")
	}()
	c.String(http.StatusAccepted, "")
}
