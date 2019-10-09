package v0

import (
	"fmt"
	"net/http"

	"github.com/deepin-cve/tracker/pkg/db"
	"github.com/gin-gonic/gin"
)

func createVersion(c *gin.Context) {
	var verInfo db.Version
	err := c.ShouldBindJSON(&verInfo)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	err = verInfo.Create()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// update cveDBSet
	err = db.SetDBHander(verInfo.Version)
	if err != nil {
		_ = verInfo.Delete()
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	insertLog(&db.Log{
		Operator:    c.GetString("username"),
		Action:      db.LogActionNewVersion,
		Target:      verInfo.Version,
		Description: db.LogActionNewVersion.String() + ": " + verInfo.Version,
		Content:     toString(&verInfo),
	})
	c.JSON(http.StatusOK, &verInfo)
}

func getVersionList(c *gin.Context) {
	list, err := db.QueryVersionList()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, &list)
}

func getVersion(c *gin.Context) {
	ver := c.Param("version")
	if len(ver) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid version",
		})
		return
	}
	info := db.Version{Version: ver}
	err := info.Get()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, &info)
}

func patchVersion(c *gin.Context) {
	ver := c.Param("version")
	if len(ver) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid version",
		})
		return
	}
	info := db.Version{Version: ver}
	err := info.Get()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	err = c.ShouldBindJSON(&info)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	err = info.Update()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	insertLog(&db.Log{
		Operator:    c.GetString("username"),
		Action:      db.LogActionPatchVersion,
		Target:      info.Version,
		Description: db.LogActionPatchVersion.String() + ": " + info.Version,
		Content:     toString(&info),
	})
	c.JSON(http.StatusOK, &info)
}

func deleteVersion(c *gin.Context) {
	ver := c.Param("version")
	if len(ver) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid version",
		})
		return
	}
	info := db.Version{Version: ver}
	err := info.Get()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	err = info.Delete()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	err = db.DeleteDBHandler(info.Version)
	if err != nil {
		fmt.Println("[Error] Failed to delete db handler:", info.Version, err)
	}

	insertLog(&db.Log{
		Operator:    c.GetString("username"),
		Action:      db.LogActionDeleteVersion,
		Target:      info.Version,
		Description: db.LogActionDeleteVersion.String() + ": " + info.Version,
		Content:     toString(&info),
	})
	c.JSON(http.StatusOK, &info)
}
