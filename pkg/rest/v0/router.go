package v0

import (
	"fmt"
	"net/http"

	"github.com/deepin-cve/tracker/internal/config"
	"github.com/deepin-cve/tracker/pkg/db"
	"github.com/deepin-cve/tracker/pkg/ldap"
	"github.com/gin-gonic/gin"
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
	v0 := eng.Group("v0")
	v0.GET("/logs", queryLogList)

	session := v0.Group("session")
	session.POST("/login", login)
	session.DELETE("/logout", logout)

	cves := v0.Group("cves")
	cves.GET("/:version", getCVEList)
	cves.GET("/:version/:id", getCVE)
	cves.PATCH("/:version/:id", checkAccessToken, patchCVE)

	versions := v0.Group("versions")
	versions.POST("", checkAccessToken, createVersion)
	versions.GET("", getVersionList)
	versions.GET("/:version", getVersion)
	versions.PATCH("/:version", checkAccessToken, patchVersion)
	versions.DELETE("/:version", checkAccessToken, deleteVersion)

	tools := v0.Group("tools")
	tools.POST("/debian/:version", checkAccessToken, fetchDebian)
	tools.POST("/package/:version", checkAccessToken, initPackages)

	return eng.Run(addr)
}

func checkAccessToken(c *gin.Context) {
	token := c.GetHeader("Access-Token")
	if len(token) == 0 {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	var tk = db.Session{Token: token}
	err := tk.Get()
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
	}
	if tk.Expired() {
		_ = tk.Delete()
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	c.Set("username", tk.Username)
}

func login(c *gin.Context) {
	var data = struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{}

	err := c.ShouldBindJSON(&data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ldapc := config.GetConfig("").LDAP
	cli, err := ldap.NewClient(ldapc.Host, ldapc.Port, ldapc.Dn, ldapc.Password, ldapc.UserSearch)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	err = cli.CheckUserPassword(data.Username, data.Password)
	cli.Close()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	tk := db.Session{
		Token:    string(db.GenToken()),
		Username: data.Username,
		Expires:  db.DefaultExpires,
	}
	err = tk.Create()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	insertLog(&db.Log{
		Operator:    data.Username,
		Action:      db.LogActionLogin,
		Target:      data.Username,
		Description: db.LogActionLogin.String(),
	})

	c.Header("Access-Token", tk.Token)
	c.String(http.StatusOK, "")
}

func logout(c *gin.Context) {
	token := c.GetHeader("Access-Token")
	if len(token) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "no token found",
		})
		return
	}

	var tk = db.Session{Token: token}
	err := tk.Get()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	err = tk.Delete()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	insertLog(&db.Log{
		Operator:    tk.Username,
		Action:      db.LogActionLogout,
		Target:      tk.Username,
		Description: db.LogActionLogout.String(),
	})

	c.String(http.StatusOK, "")
}

func queryLogList(c *gin.Context) {
	var params = make(map[string]string)
	if operator := c.Query("operator"); len(operator) != 0 {
		params["operator"] = operator
	}
	if target := c.Query("target"); len(target) != 0 {
		params["target"] = target
	}

	list, err := db.QueryLogList(params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, &list)
}

func insertLog(log *db.Log) {
	err := log.Create()
	if err != nil {
		fmt.Println("Failed to insert log:", err, log.Action.String(), log.Description)
	}
}
