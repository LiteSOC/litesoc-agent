package main

import (
	"net"
	"regexp"
	"strings"
)

// redactedValue is the placeholder written over any sensitive field.
const redactedValue = "[REDACTED]"

// rePasswordLike matches actor IDs that look more like accidental password
// entries than legitimate Unix usernames. A username that contains any of:
//   - two or more consecutive special/symbol characters, or
//   - a mix of letters/digits with password-typical symbols (@, !, $, %, ^, &, *, +, =, #, ~)
//
// is treated as potentially sensitive and masked before forwarding to the API.
// Single dots/hyphens/underscores are common in real usernames and are permitted.
var rePasswordLike = regexp.MustCompile(
	// Two consecutive symbols anywhere in the string (e.g. "P@$$word", "!admin!")
	`[!@$%^&*+=~#]{2,}` +
		// OR at least one symbol from the high-risk set mixed into an alphanumeric string
		`|(?:[A-Za-z0-9]+[!@$%^&*+=~#][A-Za-z0-9]+)` +
		// OR starts or ends with a symbol (e.g. "!root", "admin!")
		`|^[!@$%^&*+=~#]` +
		`|[!@$%^&*+=~#]$`,
)

// privateIPNets lists the CIDR ranges considered "internal" for redaction
// purposes. These should never appear as the source of an inbound SSH
// connection in a meaningful security event forwarded to an external API.
var privateIPNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range []string{
		"10.0.0.0/8",       // RFC 1918
		"172.16.0.0/12",    // RFC 1918
		"192.168.0.0/16",   // RFC 1918
		"127.0.0.0/8",      // loopback
		"::1/128",          // IPv6 loopback
		"169.254.0.0/16",   // link-local (IPv4)
		"fe80::/10",        // link-local (IPv6)
		"100.64.0.0/10",    // CGNAT (RFC 6598)
		"fc00::/7",         // unique local (IPv6)
	} {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			// Only reachable with a programmer error — the literals above are valid.
			panic("redact: invalid built-in CIDR " + cidr + ": " + err.Error())
		}
		nets = append(nets, n)
	}
	return nets
}()

// isPrivateIP returns true when addr is an internal/private address that must
// not be forwarded to the external LiteSOC API as a source IP.
func isPrivateIP(addr string) bool {
	// Strip port if present (handles "[::1]:22" or "1.2.3.4:22").
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	for _, n := range privateIPNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isPasswordLike returns true when s matches the patterns that indicate it is
// more likely to be an accidentally-typed password than a real username.
func isPasswordLike(s string) bool {
	return rePasswordLike.MatchString(s)
}

// redactPayload applies in-place redaction to a parsed IngestPayload:
//
//  1. Actor.ID that looks like a password → replaced with [REDACTED]
//  2. UserIP that is a private/internal address → replaced with [REDACTED]
//
// The function modifies the payload in place and is idempotent.
func redactPayload(p *IngestPayload) {
	if p == nil {
		return
	}

	// Redact password-like actor IDs.
	if p.Actor != nil && isPasswordLike(p.Actor.ID) {
		p.Actor.ID = redactedValue
	}

	// Redact internal/private source IPs that should not be forwarded.
	if p.UserIP != "" && isPrivateIP(p.UserIP) {
		p.UserIP = redactedValue
	}
}
