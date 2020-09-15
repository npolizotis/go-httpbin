// Package assets contains functionality for loading static content
package assets

import (
	"io/ioutil"
	"path/filepath"
)

const pathPrefix = "static"

//go:generate broccoli -src ../../static/ -o assets -var broccoli

// MustLoad loads the file.
// Panics on any error
func MustLoad(filename string) []byte {
	fs, err := broccoli.Open(filepath.Join(pathPrefix, filename))
	if err != nil {
		panic(err)
	}
	res, err := ioutil.ReadAll(fs)
	defer fs.Close()
	if err != nil {
		panic(err)
	}
	return res
}

// Load the filename or error
func Load(filename string) ([]byte, error) {
	fs, err := broccoli.Open(filepath.Join(pathPrefix, filename))
	if err != nil {
		return nil, err
	}
	res, err := ioutil.ReadAll(fs)
	defer fs.Close()
	if err != nil {
		return nil, err
	}

	return res, nil
}
