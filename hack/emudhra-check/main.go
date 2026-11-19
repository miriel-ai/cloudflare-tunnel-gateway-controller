// Command emudhra-check fails when a CA bundle still lets the compromised
// eMudhra (emSign) intermediates chain to a trusted root.
//
// In October 2026 the private keys of eight eMudhra intermediate CAs were
// shown to be recoverable. Each intermediate is signed by an eMudhra root
// that chains to "emSign ECC Root CA - G3", and is also cross-signed by
// Sectigo's "AAA Certificate Services". A bundle that still trusts either
// anchor accepts certificates anyone can forge.
//
// The check is behavioural: for each committed intermediate and cross-sign
// it searches for a signature path to a certificate in the bundle under test
// and requires every search to fail. Before that, a positive control adds the
// anchors back and requires every search to succeed, so a broken fixture
// or a searcher that rejects everything cannot pass the build quietly.
//
// crypto/x509.Verify is deliberately not used: since Go 1.27.3 it carries its
// own SPKI blocklist for these keys and would report "untrusted" whatever the
// bundle holds. The search checks signatures only (no validity dates, path
// length or name constraints), which can only make it stricter.
//
// The fixtures are public data from https://emudhra.we-have-a-problem.com/
// (impacted-intermediates.json, roots.json and the published test chains).
// Every certificate is pinned by SHA-256 below.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

//go:embed fixtures/*.pem
var fixtures embed.FS

// minBundleCerts guards against pointing the check at an empty or truncated
// file, which would pass vacuously.
const minBundleCerts = 50

// maxDepth bounds the signature path search (leaf, root-TLS, root, spare).
const maxDepth = 6

type pinned struct {
	name   string
	issuer string
	sha256 string
}

// impacted are the eight intermediates (issued by an eMudhra root) and their
// eight Sectigo cross-signs, in the order of impacted-intermediates.json.
var impacted = []pinned{
	{"EM DV TLS CA - G3B", "emSign Root TLS CA - G3", "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493"},
	{"EM DV TLS CA - G3B", "AAA Certificate Services", "45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE"},
	{"EM OV TLS CA - G3B", "emSign Root TLS CA - G3", "98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B"},
	{"EM OV TLS CA - G3B", "AAA Certificate Services", "5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699"},
	{"EM EV TLS CA - G3B", "emSign Root TLS CA - G3", "E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838"},
	{"EM EV TLS CA - G3B", "AAA Certificate Services", "579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512"},
	{"EM DV TLS CA - G3C", "emSign Root TLS CA - G3", "0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19"},
	{"EM DV TLS CA - G3C", "AAA Certificate Services", "62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72"},
	{"EM OV TLS CA - G3C", "emSign Root TLS CA - G3", "CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F"},
	{"EM OV TLS CA - G3C", "AAA Certificate Services", "7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489"},
	{"EM EV TLS CA - G3C", "emSign Root TLS CA - G3", "432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3"},
	{"EM EV TLS CA - G3C", "AAA Certificate Services", "FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F"},
	{"EM OV CS CA - G3B", "emSign Root CS CA - G3", "9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4"},
	{"EM OV CS CA - G3B", "AAA Certificate Services", "A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8"},
	{"EM OV CS CA - G3C", "emSign Root CS CA - G3", "4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1"},
	{"EM OV CS CA - G3C", "AAA Certificate Services", "84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD"},
}

// helperPins is the one intermediate needed to build chains (emSign Root TLS
// CA - G3, cross-signed by the ECC root). controlPins are the roots whose
// trust makes the impacted certificates chain: the two real anchors and the
// two self-signed eMudhra roots that issue them (trusted only by Microsoft).
var (
	helperPins = []string{
		"3094025792039A68AF6E553686410BDAB7C0D4A36B9084CBA64202E35D6EBBDD", // emSign Root TLS CA - G3, cross-signed by the ECC root
	}
	controlPins = []string{
		"86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B", // emSign ECC Root CA - G3
		"D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4", // AAA Certificate Services
		"7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D", // emSign Root TLS CA - G3 (self-signed)
		"F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5", // emSign Root CS CA - G3 (self-signed)
	}
)

func main() {
	bundle := flag.String("bundle", "/etc/ssl/certs/ca-certificates.crt", "PEM CA bundle to check")
	flag.Parse()

	if err := run(*bundle, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "emudhra-check: FAIL:", err)
		os.Exit(1)
	}
}

func run(bundlePath string, out io.Writer) error {
	bundleData, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}

	bundle, err := parseCerts(bundleData)
	if err != nil {
		return fmt.Errorf("bundle %s: %w", bundlePath, err)
	}

	if len(bundle) < minBundleCerts {
		return fmt.Errorf("bundle %s holds %d certificates, which is not a plausible root store", bundlePath, len(bundle))
	}

	subjects, helpers, control, err := loadFixtures()
	if err != nil {
		return err
	}

	return evaluate(bundle, subjects, helpers, control, out)
}

func evaluate(bundle, subjects, helpers, control []*x509.Certificate, out io.Writer) error {
	// Positive control: with the anchors added, every search must succeed.
	withAnchors := append(append([]*x509.Certificate{}, bundle...), control...)

	for _, cert := range subjects {
		if !chainsToRoot(cert, helpers, withAnchors, maxDepth, nil) {
			return fmt.Errorf("positive control broken: %q (issued by %s) does not chain even with the anchors added",
				cert.Subject.CommonName, cert.Issuer.CommonName)
		}
	}

	fmt.Fprintf(out, "positive control: all %d impacted certificates chain when the anchors are added\n", len(subjects))

	var trusted []string

	for _, cert := range subjects {
		if chainsToRoot(cert, helpers, bundle, maxDepth, nil) {
			trusted = append(trusted, fmt.Sprintf("%s (issued by %s)", cert.Subject.CommonName, cert.Issuer.CommonName))
		}
	}

	if len(trusted) > 0 {
		return fmt.Errorf("the CA bundle still trusts %d of %d impacted certificates:\n  %s",
			len(trusted), len(subjects), strings.Join(trusted, "\n  "))
	}

	fmt.Fprintf(out, "bundle: none of the %d impacted certificates chains to a trusted root (%d roots in the bundle)\n",
		len(subjects), len(bundle))

	return nil
}

// chainsToRoot reports whether cert is a root, is signed by a root, or is
// signed by a helper that (recursively) is.
func chainsToRoot(cert *x509.Certificate, helpers, roots []*x509.Certificate, depth int, seen [][]byte) bool {
	if depth == 0 {
		return false
	}

	for _, root := range roots {
		if bytes.Equal(root.Raw, cert.Raw) || cert.CheckSignatureFrom(root) == nil {
			return true
		}
	}

	seen = append(seen, cert.Raw)

	for _, helper := range helpers {
		if containsRaw(seen, helper.Raw) || cert.CheckSignatureFrom(helper) != nil {
			continue
		}

		if chainsToRoot(helper, helpers, roots, depth-1, seen) {
			return true
		}
	}

	return false
}

func containsRaw(list [][]byte, raw []byte) bool {
	for _, item := range list {
		if bytes.Equal(item, raw) {
			return true
		}
	}

	return false
}

func loadFixtures() (subjects, helpers, control []*x509.Certificate, err error) {
	subjects, err = loadPinned("fixtures/impacted.pem", pins(impacted))
	if err != nil {
		return nil, nil, nil, err
	}

	helpers, err = loadPinned("fixtures/helpers.pem", helperPins)
	if err != nil {
		return nil, nil, nil, err
	}

	control, err = loadPinned("fixtures/control-roots.pem", controlPins)
	if err != nil {
		return nil, nil, nil, err
	}

	return subjects, helpers, control, nil
}

func pins(list []pinned) []string {
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, item.sha256)
	}

	return out
}

// loadPinned parses an embedded PEM file and requires its certificates to be
// exactly the pinned set (by SHA-256 of the DER encoding).
func loadPinned(path string, want []string) ([]*x509.Certificate, error) {
	data, err := fixtures.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	certs, err := parseCerts(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	got := make(map[string]bool, len(certs))

	for _, cert := range certs {
		sum := sha256.Sum256(cert.Raw)
		got[strings.ToUpper(hex.EncodeToString(sum[:]))] = true
	}

	if len(certs) != len(want) || len(got) != len(want) {
		return nil, fmt.Errorf("%s: holds %d certificates (%d distinct), want %d", path, len(certs), len(got), len(want))
	}

	for _, pin := range want {
		if !got[pin] {
			return nil, fmt.Errorf("%s: pinned certificate %s is missing or was replaced", path, pin)
		}
	}

	return certs, nil
}

func parseCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for {
		var block *pem.Block

		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates found")
	}

	return certs, nil
}
