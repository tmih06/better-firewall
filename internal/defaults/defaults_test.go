package defaults

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRead(t *testing.T) {
	data, err := Read("better-firewall.default")
	if err != nil {
		t.Fatalf("Read(better-firewall.default): %v", err)
	}
	if !strings.Contains(string(data), "IPV6=yes") {
		t.Errorf("better-firewall.default missing IPV6=yes:\n%s", data)
	}

	data, err = Read("applications.d/openssh.ini")
	if err != nil {
		t.Fatalf("Read(openssh.ini): %v", err)
	}
	if !strings.Contains(string(data), "[OpenSSH]") || !strings.Contains(string(data), "22/tcp") {
		t.Errorf("openssh.ini unexpected content:\n%s", data)
	}

	if _, err := Read("does-not-exist"); err == nil {
		t.Error("Read(missing): got nil error")
	}
}

func TestProfiles(t *testing.T) {
	profs, err := Profiles()
	if err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	if len(profs) == 0 {
		t.Fatal("Profiles: empty")
	}
	ssh, ok := profs["openssh.ini"]
	if !ok {
		t.Fatalf("openssh.ini not embedded; got %v", func() []string {
			var names []string
			for n := range profs {
				names = append(names, n)
			}
			return names
		}())
	}
	if !strings.Contains(string(ssh), "ports=") {
		t.Error("openssh.ini profile missing ports=")
	}
	// Non-profile defaults must not leak into the profile map.
	for name := range profs {
		if !strings.HasSuffix(name, ".ini") {
			t.Errorf("non-ini entry in profiles: %q", name)
		}
	}
}

func TestMaterializeCreatesTree(t *testing.T) {
	dir := t.TempDir()
	created, err := Materialize(dir)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if len(created) == 0 {
		t.Fatal("Materialize created nothing")
	}
	for _, want := range []string{
		"better-firewall.default",
		"sysctl.conf",
		"applications.d/openssh.ini",
		"applications.d/nginx.ini",
		"applications.d/mail.ini",
		"applications.d/misc.ini",
	} {
		p := filepath.Join(dir, want)
		data, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("expected %s: %v", p, err)
			continue
		}
		// Materialized content must be byte-identical to the embedded copy.
		orig, err := Read(want)
		if err != nil {
			t.Fatalf("Read(%s): %v", want, err)
		}
		if string(data) != string(orig) {
			t.Errorf("%s content differs from embedded file", want)
		}
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o644 {
			t.Errorf("%s perm = %o, want 644", want, fi.Mode().Perm())
		}
	}
}

func TestMaterializePreservesExisting(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "applications.d")
	if err := os.MkdirAll(appDir, 0755); err != nil {
		t.Fatal(err)
	}
	custom := []byte("[Custom]\ntitle=mine\ndescription=user-edited\nports=9/tcp\n")
	target := filepath.Join(appDir, "openssh.ini")
	if err := os.WriteFile(target, custom, 0600); err != nil {
		t.Fatal(err)
	}

	created, err := Materialize(dir)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if data, _ := os.ReadFile(target); string(data) != string(custom) {
		t.Error("Materialize overwrote a user-modified file")
	}
	for _, c := range created {
		if c == target {
			t.Error("existing file reported as created")
		}
	}

	// Idempotent: a second run over a fully materialized tree creates nothing.
	created, err = Materialize(dir)
	if err != nil {
		t.Fatalf("second Materialize: %v", err)
	}
	if len(created) != 0 {
		t.Errorf("second Materialize created %v, want none", created)
	}
}

func TestMaterializeErrorWhenDirIsFile(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	// A file in place of the target directory → MkdirAll fails.
	if _, err := Materialize(blocker); err == nil {
		t.Fatal("Materialize onto a file path: got nil error")
	}
}
