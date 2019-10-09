package v0

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/deepin-cve/tracker/pkg/cve"
	"github.com/deepin-cve/tracker/pkg/db"
	"github.com/gin-gonic/gin"
)

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

	version := c.Param("version")
	if len(version) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid version",
		})
		return
	}

	infos, total, err := cve.QueryCVEList(params, (page-1)*count, count, version)
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
	version := c.Param("version")
	if len(id) == 0 || len(version) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid version",
		})
		return
	}

	info, err := db.NewCVE(id, version)
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
	version := c.Param("version")
	if len(id) == 0 || len(version) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid version",
		})
		return
	}

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

	info, err := cve.UpdateCVE(id, version, values)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	insertLog(&db.Log{
		Operator:    c.GetString("username"),
		Action:      db.LogActionPatchCVE,
		Target:      id,
		Description: db.LogActionPatchCVE.String() + ": " + id,
		Content:     toString(&values),
	})

	c.JSON(http.StatusOK, info)
}
