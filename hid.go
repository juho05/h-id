package hid

import (
	"embed"
	"encoding/json"
	"io/fs"

	"github.com/Bananenpro/log"
)

//go:embed data/html
var htmlFS embed.FS

//go:embed data/static
var staticFS embed.FS

//go:embed data/email
var emailFS embed.FS

var (
	HTMLFS   fs.FS
	StaticFS fs.FS
	EmailFS  fs.FS
)

//go:embed data/openid_configuration.json
var OpenIDConfiguration []byte

//go:embed data/default_profile_picture.jpg
var DefaultProfilePicture []byte

func init() {
	var err error
	HTMLFS, err = fs.Sub(htmlFS, "data/html")
	if err != nil {
		log.Fatal(err)
	}
	StaticFS, err = fs.Sub(staticFS, "data/static")
	if err != nil {
		log.Fatal(err)
	}
	EmailFS, err = fs.Sub(emailFS, "data/email")
	if err != nil {
		log.Fatal(err)
	}

	var oidConfig map[string]any
	err = json.Unmarshal(OpenIDConfiguration, &oidConfig)
	if err != nil {
		log.Fatal(err)
	}
	OpenIDConfiguration, err = json.Marshal(oidConfig)
	if err != nil {
		log.Fatal(err)
	}
}
