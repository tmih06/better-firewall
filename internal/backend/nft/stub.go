package nft

import (
	"errors"

	"bfirewall/internal/backend"
	"bfirewall/internal/store"
)

// Method stubs — replaced by apply.go/readback.go/compile.go.

func (b *be) Apply(st *store.State, etc map[string]string) error {
	return errors.New("not implemented")
}

func (b *be) Flush() error { return errors.New("not implemented") }

func (b *be) Loaded() (bool, error) { return false, errors.New("not implemented") }

func (b *be) ReadBack() (*backend.Snapshot, error) {
	return nil, errors.New("not implemented")
}

func (b *be) ApplyFragments(path string) error { return errors.New("not implemented") }
