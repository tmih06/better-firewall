package appprof

import (
	"os"
	"path/filepath"
	"testing"
)

// writeProfiles creates dir with the given ini files and a services
// database under a shared BFW_PREFIX so collision checks are hermetic.
func setup(t *testing.T, servicesFile string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "services"), []byte(servicesFile), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "apps.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("BFW_PREFIX", root)
	return dir
}

const testServices = "smtp\t25/tcp\nssh\t22/tcp\ndomain\t53/tcp\ndomain\t53/udp\n"

func TestLoadBasic(t *testing.T) {
	dir := setup(t, testServices, map[string]string{
		"apache.ini": "[Apache]\ntitle=Web Server\ndescription=Apache web server\nports=80/tcp|443/tcp\n",
	})
	profs, skipped, err := LoadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %v", skipped)
	}
	if len(profs) != 1 {
		t.Fatalf("got %d profiles", len(profs))
	}
	p := profs[0]
	if p.Name != "Apache" || p.Title != "Web Server" || p.Description != "Apache web server" {
		t.Fatalf("profile = %+v", p)
	}
	specs := p.Expand()
	if len(specs) != 2 {
		t.Fatalf("Expand() = %v", specs)
	}
	if specs[0].Ports != "80" || specs[0].Proto != "tcp" {
		t.Fatalf("spec[0] = %+v", specs[0])
	}
	if specs[1].Ports != "443" || specs[1].Proto != "tcp" {
		t.Fatalf("spec[1] = %+v", specs[1])
	}
}

func TestLoadManPagePorts(t *testing.T) {
	// Man page example: ports=12/udp|34|56,78:90/tcp
	dir := setup(t, testServices, map[string]string{
		"app.ini": "[MyApp]\ntitle=T\ndescription=D\nports=12/udp|34|56,78:90/tcp\n",
	})
	profs, _, err := LoadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(profs) != 1 {
		t.Fatalf("got %d profiles", len(profs))
	}
	specs := profs[0].Expand()
	want := []PortSpec{
		{Ports: "12", Proto: "udp"},
		{Ports: "34", Proto: "any"},
		{Ports: "56,78:90", Proto: "tcp"},
	}
	if len(specs) != len(want) {
		t.Fatalf("Expand() = %+v", specs)
	}
	for i, w := range want {
		if specs[i] != w {
			t.Fatalf("spec[%d] = %+v, want %+v", i, specs[i], w)
		}
	}
}

func TestListRangeRequiresProto(t *testing.T) {
	for _, ports := range []string{"56,78", "78:90", "56,78:90"} {
		dir := setup(t, testServices, map[string]string{
			"app.ini": "[App]\ntitle=T\ndescription=D\nports=" + ports + "\n",
		})
		profs, _, err := LoadAll(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(profs) != 0 {
			t.Fatalf("ports=%q: profile should be rejected, got %+v", ports, profs[0])
		}
	}
}

func TestMissingFieldsSkipped(t *testing.T) {
	dir := setup(t, testServices, map[string]string{
		"bad.ini":  "[NoPorts]\ntitle=T\ndescription=D\n",
		"bad2.ini": "[EmptyTitle]\ntitle=\ndescription=D\nports=80/tcp\n",
		"good.ini": "[Good]\ntitle=T\ndescription=D\nports=80/tcp\n",
	})
	profs, _, err := LoadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(profs) != 1 || profs[0].Name != "Good" {
		t.Fatalf("profs = %+v", profs)
	}
}

func TestInvalidNamesSkipped(t *testing.T) {
	dir := setup(t, testServices, map[string]string{
		"apps.ini": "[all]\ntitle=T\ndescription=D\nports=80/tcp\n" +
			"[1234]\ntitle=T\ndescription=D\nports=80/tcp\n" +
			"[bad name!]\ntitle=T\ndescription=D\nports=80/tcp\n" +
			"[Valid Name]\ntitle=T\ndescription=D\nports=80/tcp\n",
	})
	profs, _, err := LoadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(profs) != 1 || profs[0].Name != "Valid Name" {
		t.Fatalf("profs = %+v", profs)
	}
}

func TestNameTooLongSkipped(t *testing.T) {
	long := make([]byte, 65)
	for i := range long {
		long[i] = 'a'
	}
	dir := setup(t, testServices, map[string]string{
		"apps.ini": "[" + string(long) + "]\ntitle=T\ndescription=D\nports=80/tcp\n",
	})
	profs, _, err := LoadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(profs) != 0 {
		t.Fatalf("profs = %+v", profs)
	}
}

func TestServicesCollisionSkipped(t *testing.T) {
	dir := setup(t, testServices, map[string]string{
		"apps.ini": "[smtp]\ntitle=T\ndescription=D\nports=25/tcp\n" +
			"[Other]\ntitle=T\ndescription=D\nports=80/tcp\n",
	})
	profs, skipped, err := LoadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 1 || skipped[0] != "smtp" {
		t.Fatalf("skipped = %v", skipped)
	}
	if len(profs) != 1 || profs[0].Name != "Other" {
		t.Fatalf("profs = %+v", profs)
	}
}

func TestFirstDirWins(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "services"), []byte(testServices), 0o644); err != nil {
		t.Fatal(err)
	}
	d1 := filepath.Join(root, "d1")
	d2 := filepath.Join(root, "d2")
	for _, d := range []string{d1, d2} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(d1, "a.ini"), []byte("[App]\ntitle=First\ndescription=D\nports=80/tcp\n"), 0o644)
	os.WriteFile(filepath.Join(d2, "a.ini"), []byte("[App]\ntitle=Second\ndescription=D\nports=443/tcp\n"), 0o644)
	t.Setenv("BFW_PREFIX", root)

	profs, err := Load(d1, d2)
	if err != nil {
		t.Fatal(err)
	}
	if len(profs) != 1 || profs[0].Title != "First" {
		t.Fatalf("profs = %+v", profs)
	}
}

func TestFindCaseInsensitive(t *testing.T) {
	profs := []*Profile{{Name: "Apache"}, {Name: "Nginx Full"}}
	if Find(profs, "apache") != profs[0] {
		t.Fatal("Find(apache) failed")
	}
	if Find(profs, "NGINX FULL") != profs[1] {
		t.Fatal("Find(NGINX FULL) failed")
	}
	if Find(profs, "other") != nil {
		t.Fatal("Find(other) should be nil")
	}
}

func TestNonIniIgnored(t *testing.T) {
	dir := setup(t, testServices, map[string]string{
		"notes.txt": "[App]\ntitle=T\ndescription=D\nports=80/tcp\n",
		"app.ini":   "[App]\ntitle=T\ndescription=D\nports=80/tcp\n",
	})
	profs, _, err := LoadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(profs) != 1 {
		t.Fatalf("profs = %+v", profs)
	}
}

func TestMissingDir(t *testing.T) {
	profs, skipped, err := LoadAll("/nonexistent-dir-xyz")
	if err != nil {
		t.Fatal(err)
	}
	if len(profs) != 0 || len(skipped) != 0 {
		t.Fatalf("profs=%v skipped=%v", profs, skipped)
	}
}

func TestValidName(t *testing.T) {
	good := []string{"Apache", "Nginx Full", "a", "A1", "app.name", "app+name", "app_name", "app-name"}
	for _, n := range good {
		if !ValidName(n) {
			t.Fatalf("ValidName(%q) = false", n)
		}
	}
	bad := []string{"all", "80", "1234", "", " name", "na!me", "na/me", "na:me"}
	for _, n := range bad {
		if ValidName(n) {
			t.Fatalf("ValidName(%q) = true", n)
		}
	}
}
