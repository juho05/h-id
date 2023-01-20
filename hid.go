package hid

import (
	"embed"
	"io/fs"

	"github.com/Bananenpro/log"
)

//go:embed ui/html
var htmlFS embed.FS

//go:embed ui/static
var staticFS embed.FS

var (
	HTMLFS   fs.FS
	StaticFS fs.FS
)

func init() {
	var err error
	HTMLFS, err = fs.Sub(htmlFS, "ui/html")
	if err != nil {
		log.Fatal(err)
	}
	StaticFS, err = fs.Sub(staticFS, "ui/static")
	if err != nil {
		log.Fatal(err)
	}
}
