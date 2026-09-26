package nft

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestWriteQuotedBytesMatchesStrconv(t *testing.T) {
	cases := [][]byte{
		[]byte("eth0"),
		[]byte(`eth\"0`),
		[]byte("line\nfeed"),
		[]byte("café"),
		{0xff, 0x00, 0x01},
	}
	for _, data := range cases {
		var got strings.Builder
		writeQuotedBytes(&got, data)
		trimmed := strings.TrimRight(string(data), "\x00")
		want := strconv.Quote(trimmed)
		if got.String() != want {
			t.Errorf("writeQuotedBytes(%q) = %q, want %q", data, got.String(), want)
		}
	}
}

func TestWriteIPMatchesNetIP(t *testing.T) {
	cases := [][]byte{
		{192, 0, 2, 1},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 1},
	}
	for _, data := range cases {
		var got strings.Builder
		if !writeIP(&got, data) {
			t.Fatalf("writeIP(%v) rejected a valid address", data)
		}
		if got.String() != net.IP(data).String() {
			t.Errorf("writeIP(%v) = %q, want %q", data, got.String(), net.IP(data).String())
		}
	}
	if writeIP(new(strings.Builder), []byte{1, 2, 3}) {
		t.Error("writeIP accepted a malformed address length")
	}
}
