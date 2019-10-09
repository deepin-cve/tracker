package v0

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"encoding/json"

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
	v0 := eng.Group("v0", cors())
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
	tools.POST("/score/:version", checkAccessToken, fetchScore)

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
		Content:     tk.Username + " login",
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
		Content:     tk.Username + " logout",
	})

	c.String(http.StatusOK, "")
}

func queryLogList(c *gin.Context) {
	var params = make(map[string]interface{})
	if operator := c.Query("operator"); len(operator) != 0 {
		params["operator"] = operator
	}
	if target := c.Query("target"); len(target) != 0 {
		params["target"] = target
	}
	if str := c.Query("action"); len(str) != 0 {
		action, _ := strconv.Atoi(str)
		if db.ValidAction(action) {
			params["action"] = action
		}
	}

	pageStr := c.DefaultQuery("page", "1")
	page, _ := strconv.Atoi(pageStr)
	countStr := c.DefaultQuery("count", fmt.Sprint(defaultPageCount))
	count, _ := strconv.Atoi(countStr)

	total, list, err := db.QueryLogList(params, (page-1)*count, count)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.Header("X-Current-Page", fmt.Sprint(page))
	c.Header("X-Resource-Total", fmt.Sprint(total))
	c.Header("X-Page-Size", fmt.Sprint(count))
	c.JSON(http.StatusOK, &list)
}

func insertLog(log *db.Log) {
	err := log.Create()
	if err != nil {
		fmt.Println("Failed to insert log:", err, log.Action.String(), log.Description)
	}
}

func cors() gin.HandlerFunc {
	// TODO(jouyouyun): using gin cors
	return func(c *gin.Context) {
		var headerList []string
		for k := range c.Request.Header {
			headerList = append(headerList, k)
		}
		var header = strings.Join(headerList, ", ")
		if len(header) != 0 {
			header = fmt.Sprintf("access-control-allow-origin, access-control-allow-headers, %s",
				header)
		} else {
			header = fmt.Sprintf("access-control-allow-origin, access-control-allow-headers")
		}

		if len(c.Request.Header.Get("Origin")) != 0 {
			c.Header("Access-Control-Allow-Origin", "*")
			c.Header("Access-Control-Allow-Headers", header)
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PATCH")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Length, X-CSRF-Token, Accept, Origin, Host, Connection, Accept-Encoding, Accept-Language,DNT, X-CustomHeader, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Content-Type, Pragma, Timestamp, timestamp")
			c.Header("Access-Control-Allow-Credentials", "true")
			// expose custom header
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Content-Type, X-Current-Page, X-Resource-Total, X-Page-Size, Access-Token")
			c.Set("Content-type", "application/json; charset=utf-8")
		}

		if c.Request.Method == http.MethodOptions {
			c.JSON(http.StatusOK, "Options Request!")
			return
		}
		c.Next()
	}
}

func toString(v interface{}) string {
	data, _ := json.Marshal(v)
	return string(data)
}
