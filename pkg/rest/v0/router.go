package v0

import (
	"fmt"

	"strconv"

	"strings"

	"net/http"

	"github.com/deepin-cve/tracker/internal/config"
	"github.com/deepin-cve/tracker/pkg/cve"
	"github.com/deepin-cve/tracker/pkg/db"
	"github.com/deepin-cve/tracker/pkg/fetcher"
	"github.com/deepin-cve/tracker/pkg/packages"
	"github.com/gin-gonic/gin"
)

const (
	defaultPageCount = 15
)

func checkAccessToken(c *gin.Context) {
	token := c.GetHeader("Access-Token")
	if token != config.GetConfig("").AccessToken {
		c.AbortWithStatus(http.StatusBadRequest)
	}
}

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
	cve.PATCH("/:id", checkAccessToken, patchCVE)

	tools := v0.Group("tools")
	tools.POST("/cve/fetch", checkAccessToken, fetchCVE)
	tools.POST("/packages", checkAccessToken, initPackages)

	return eng.Run(addr)
}

func getCVEList(c *gin.Context) {
	// query parameters: package, status(multi status), remote, pre_installed, archived, filters(only urgency), page, count, sort
	// status and filters split by ','
	// sort available values only should be table column name, such as: package, updated_at, urgency etc.
	var params = make(map[string]interface{})

	pkg := c.Query("package")
	if len(pkg) != 0 {
		params["package"] = pkg
	}
	remote := c.Query("remote")
	if len(remote) != 0 {
		params["remote"] = remote
	}
	preInstalled := c.Query("pre_installed")
	if preInstalled == "true" {
		params["pre_installed"] = true
	} else if preInstalled == "false" {
		params["pre_installed"] = false
	}
	archived := c.Query("archived")
	if archived == "true" {
		params["archived"] = true
	} else if archived == "false" {
		params["archived"] = false
	}
	sort := c.Query("sort")
	if len(sort) != 0 {
		if db.ValidColumn(sort) {
			params["sort"] = sort
		}
	}

	pageStr := c.DefaultQuery("page", "1")
	page, _ := strconv.Atoi(pageStr)
	countStr := c.DefaultQuery("count", fmt.Sprint(defaultPageCount))
	count, _ := strconv.Atoi(countStr)

	statusList := c.Query("status")
	if len(statusList) != 0 {
		params["status"] = strings.Split(statusList, ",")
	}

	filters := c.Query("filters")
	if len(filters) != 0 {
		params["filters"] = strings.Split(filters, ",")
	}

	infos, total, err := cve.QueryCVEList(params, (page-1)*count, count)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.Header("X-Current-Page", fmt.Sprint(page))
	c.Header("X-Resource-Total", fmt.Sprint(total))
	c.Header("X-Page-Size", fmt.Sprint(count))
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
	err := c.ShouldBind(&values)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	if len(values) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "no data has bind",
		})
		return
	}

	// check status
	value, ok := values["status"]
	if ok {
		status, ok := value.(string)
		if ok && len(status) != 0 {
			if !db.ValidStatus(status) {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "invalid status: " + status,
				})
				return
			}
		}
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
