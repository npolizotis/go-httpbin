// +build ignore

package main

import (
	"log"

	data "github.com/npolizotis/go-httpbin/httpbin/assets"
	"github.com/shurcooL/vfsgen"
)

func main() {
	err := vfsgen.Generate(data.Assets, vfsgen.Options{
		PackageName:  "assets",
		BuildTags:    "!dev",
		VariableName: "Assets",
	})
	if err != nil {
		log.Fatalln(err)
	}
}
