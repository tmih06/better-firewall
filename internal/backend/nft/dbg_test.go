package nft

import (
	"os"
	"testing"
	"bfirewall/internal/store"
)

func TestDebugRender(t *testing.T) {
	s, err := RenderText(store.Defaults(), nil)
	if err != nil { t.Fatal(err) }
	os.WriteFile("/tmp/render.txt", []byte(s), 0644)
}
