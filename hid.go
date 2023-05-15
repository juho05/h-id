package hid

import (
	"bytes"
	"embed"
	"encoding/json"
	"io/fs"
	"text/template"
	"time"

	"github.com/Bananenpro/log"

	"github.com/juho05/h-id/config"
)

var StartTime = time.Now()

//go:embed data
var dataFS embed.FS

var (
	HTMLFS   fs.FS
	StaticFS fs.FS
	EmailFS  fs.FS
)

var OpenIDConfiguration []byte

//go:embed data/default_profile_picture.jpg
var DefaultProfilePicture []byte

func Initialize() {
	var err error
	HTMLFS, err = fs.Sub(dataFS, "data/html")
	if err != nil {
		log.Fatal(err)
	}
	StaticFS, err = fs.Sub(dataFS, "data/static")
	if err != nil {
		log.Fatal(err)
	}
	EmailFS, err = fs.Sub(dataFS, "data/email")
	if err != nil {
		log.Fatal(err)
	}

	openIDConfig, err := template.ParseFS(dataFS, "data/openid_configuration.tmpl.json")
	if err != nil {
		log.Fatal(err)
	}
	type tmplData struct {
		BaseURL string
	}
	buffer := bytes.Buffer{}
	err = openIDConfig.Execute(&buffer, tmplData{
		BaseURL: config.BaseURL(),
	})
	if err != nil {
		log.Fatal(err)
	}

	var oidConfig map[string]any
	err = json.Unmarshal(buffer.Bytes(), &oidConfig)
	if err != nil {
		log.Fatal(err)
	}
	OpenIDConfiguration, err = json.Marshal(oidConfig)
	if err != nil {
		log.Fatal(err)
	}
}
