package main

import (
	"flag"

	"fmt"

	"github.com/jouyouyun/deepin-cve-tracker/internal/config"
	"github.com/jouyouyun/deepin-cve-tracker/pkg/db"
	v0 "github.com/jouyouyun/deepin-cve-tracker/pkg/rest/v0"
)

var (
	conf  = flag.String("c", "/etc/deepin-cve-tracker/config.yaml", "the configuration filepath")
	debug = flag.Bool("d", false, "enable debug mode")
)

func main() {
	flag.Parse()

	var c = config.GetConfig(*conf)
	db.Init(c.DB.PackageFile, c.DB.CVEFile)

	err := v0.Route(fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port),
		*debug)
	if err != nil {
		fmt.Println("Failed to route:", err)
	}
}
