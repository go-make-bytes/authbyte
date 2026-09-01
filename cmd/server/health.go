package main

import (
	app "github.com/go-make-bytes/authbyte"

	"azugo.io/azugo/server"
	"azugo.io/core/cli"
)

func init() {
	cli.Register(server.HealthCommand("/healthz", server.Options{
		AppName:       "Identity/Auth Service",
		AppVer:        Version,
		Configuration: app.NewConfiguration(),
	}))
}
