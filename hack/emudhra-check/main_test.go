package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func selfSigned(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated test root"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

func TestEvaluate(t *testing.T) {
	t.Parallel()

	subjects, helpers, control, err := loadFixtures()
	if err != nil {
		t.Fatalf("fixtures do not match their pins: %v", err)
	}

	if len(subjects) != 16 {
		t.Fatalf("got %d impacted certificates, want 16", len(subjects))
	}

	unrelated := []*x509.Certificate{selfSigned(t)}

	tests := []struct {
		name    string
		bundle  []*x509.Certificate
		wantErr string
	}{
		{name: "bundle without either anchor passes", bundle: unrelated},
		{name: "ECC root trusted fails", bundle: append([]*x509.Certificate{control[0]}, unrelated...), wantErr: "still trusts"},
		{name: "AAA root trusted fails", bundle: append([]*x509.Certificate{control[1]}, unrelated...), wantErr: "still trusts"},
		{name: "an impacted intermediate trusted directly fails", bundle: append([]*x509.Certificate{subjects[0]}, unrelated...), wantErr: "still trusts"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer

			err := evaluate(tt.bundle, subjects, helpers, control, &out)

			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected failure: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("got %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

// With no anchors to add back nothing can chain, so the positive control has
// to fail the run instead of letting "nothing chains" pass as "distrusted".
func TestEvaluateRejectsBrokenControl(t *testing.T) {
	t.Parallel()

	subjects, helpers, _, err := loadFixtures()
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer

	err = evaluate([]*x509.Certificate{selfSigned(t)}, subjects, helpers, nil, &out)
	if err == nil || !strings.Contains(err.Error(), "positive control broken") {
		t.Fatalf("got %v, want a positive control failure", err)
	}
}

func TestRunRejectsImplausibleBundle(t *testing.T) {
	t.Parallel()

	err := run("fixtures/control-roots.pem", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "plausible root store") {
		t.Fatalf("got %v, want a refusal to check a 2-certificate bundle", err)
	}
}
