package rule

import (
	"fmt"
	"strconv"
	"strings"
)

var icmpTypesV4 = map[string]uint8{
	"echo-reply": 0, "destination-unreachable": 3, "source-quench": 4,
	"redirect": 5, "echo-request": 8, "router-advertisement": 9,
	"router-solicitation": 10, "time-exceeded": 11,
	"parameter-problem": 12, "timestamp-request": 13,
	"timestamp-reply": 14, "information-request": 15, "info-request": 15,
	"information-reply": 16, "info-reply": 16, "address-mask-request": 17,
	"address-mask-reply": 18,
}

var icmpTypesV6 = map[string]uint8{
	"destination-unreachable": 1, "packet-too-big": 2, "time-exceeded": 3,
	"parameter-problem": 4, "echo-request": 128, "echo-reply": 129,
	"mld-listener-query": 130, "mld-listener-report": 131,
	"mld2-listener-report": 143, "mldv2-listener-report": 143,
	"mld-listener-done": 132, "router-solicitation": 133,
	"router-advertisement": 134, "nd-router-solicit": 133, "nd-router-advert": 134,
	"neighbour-solicitation": 135, "neighbor-solicitation": 135,
	"nd-neighbor-solicit": 135, "neighbour-advertisement": 136,
	"neighbor-advertisement": 136, "nd-neighbor-advert": 136,
	"redirect": 137, "router-renumbering": 138,
	"node-information-query": 139, "node-information-reply": 140,
	"inverse-neighbor-discovery-solicitation": 141, "ind-neighbor-solicit": 141,
	"inverse-neighbor-discovery-advertisement": 142, "ind-neighbor-advert": 142,
	"home-agent-address-discovery-request": 144,
	"home-agent-address-discovery-reply":   145,
	"mobile-prefix-solicitation":           146, "mobile-prefix-advertisement": 147,
	"certification-path-solicitation": 148, "certification-path-advertisement": 149,
	"multicast-router-advertisement": 151, "multicast-router-solicitation": 152,
	"multicast-router-termination": 153,
}

// ICMPTypeNumber returns the canonical decimal representation of an ICMP
// type. Names are the standard nftables/iptables/firewalld names for proto.
func ICMPTypeNumber(proto, token string) (string, error) {
	var names map[string]uint8
	switch proto {
	case "icmp":
		names = icmpTypesV4
	case "icmpv6":
		names = icmpTypesV6
	default:
		return "", fmt.Errorf("ICMP type requires proto icmp or icmpv6, got %q", proto)
	}
	if n, err := strconv.ParseUint(token, 10, 8); err == nil {
		return strconv.FormatUint(n, 10), nil
	}
	if n, ok := names[strings.ToLower(token)]; ok {
		return strconv.FormatUint(uint64(n), 10), nil
	}
	return "", fmt.Errorf("unknown %s type %q", proto, token)
}
