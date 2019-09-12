package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/deepin-cve/tracker/internal/config"
	"github.com/deepin-cve/tracker/pkg/db"
	v0 "github.com/deepin-cve/tracker/pkg/rest/v0"
)

var (
	conf  = flag.String("c", "/etc/deepin-cve-tracker/config.yaml", "the configuration filepath")
	debug = flag.Bool("d", false, "enable debug mode")
)

func main() {
	flag.Parse()

	var c = config.GetConfig(*conf)
	db.Init(c.DBDir)

	go func() {
		for {
			time.Sleep(time.Hour * 10)
			err := db.SessionClean()
			if err != nil {
				fmt.Println("Failed to clean session:", err)
			}
		}
	}()

	err := v0.Route(fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port),
		*debug)
	if err != nil {
		fmt.Println("Failed to route:", err)
	}
}
