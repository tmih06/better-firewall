// Package defaults embeds the shipped protection and firewall configuration,
// application profiles, sysctl.conf, and /etc/default/better-firewall. Files
// are materialized lazily — created on first use if missing, never overwriting
// user edits.
package defaults

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed files
var files embed.FS

// Read returns an embedded file's contents ("applications.d/openssh.ini").
func Read(name string) ([]byte, error) {
	return files.ReadFile(filepath.Join("files", name))
}

// Materialize writes embedded defaults into dir, skipping files that
// already exist. Returns the list of files created.
func Materialize(dir string) ([]string, error) {
	var created []string
	err := fs.WalkDir(files, "files", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel("files", path)
		dest := filepath.Join(dir, rel)
		if _, err := os.Stat(dest); err == nil {
			return nil // user file exists — never overwrite
		}
		data, err := files.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(dest, data, 0644); err != nil {
			return err
		}
		created = append(created, dest)
		return nil
	})
	return created, err
}

// Profiles returns the embedded application profile files as
// name → contents.
func Profiles() (map[string][]byte, error) {
	out := map[string][]byte{}
	entries, err := files.ReadDir("files/applications.d")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := files.ReadFile("files/applications.d/" + e.Name())
		if err != nil {
			return nil, err
		}
		out[e.Name()] = data
	}
	return out, nil
}
