// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/hostinfo"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestNewDirect(t *testing.T) {
	hi := hostinfo.New()
	ni := tailcfg.NetInfo{LinkType: "wired"}
	hi.NetInfo = &ni

	k := key.NewMachine()
	opts := Options{
		ServerURL: "https://example.com",
		Hostinfo:  hi,
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return k, nil
		},
		Dialer: tsdial.NewDialer(netmon.NewStatic()),
	}
	c, err := NewDirect(opts)
	if err != nil {
		t.Fatal(err)
	}

	if c.serverURL != opts.ServerURL {
		t.Errorf("c.serverURL got %v want %v", c.serverURL, opts.ServerURL)
	}

	// hi is stored without its NetInfo field.
	hiWithoutNi := *hi
	hiWithoutNi.NetInfo = nil
	if !hiWithoutNi.Equal(c.hostinfo) {
		t.Errorf("c.hostinfo got %v want %v", c.hostinfo, hi)
	}

	changed := c.SetNetInfo(&ni)
	if changed {
		t.Errorf("c.SetNetInfo(ni) want false got %v", changed)
	}
	ni = tailcfg.NetInfo{LinkType: "wifi"}
	changed = c.SetNetInfo(&ni)
	if !changed {
		t.Errorf("c.SetNetInfo(ni) want true got %v", changed)
	}

	changed = c.SetHostinfo(hi)
	if changed {
		t.Errorf("c.SetHostinfo(hi) want false got %v", changed)
	}
	hi = hostinfo.New()
	hi.Hostname = "different host name"
	changed = c.SetHostinfo(hi)
	if !changed {
		t.Errorf("c.SetHostinfo(hi) want true got %v", changed)
	}

	endpoints := fakeEndpoints(1, 2, 3)
	changed = c.newEndpoints(endpoints)
	if !changed {
		t.Errorf("c.newEndpoints want true got %v", changed)
	}
	changed = c.newEndpoints(endpoints)
	if changed {
		t.Errorf("c.newEndpoints want false got %v", changed)
	}
	endpoints = fakeEndpoints(4, 5, 6)
	changed = c.newEndpoints(endpoints)
	if !changed {
		t.Errorf("c.newEndpoints want true got %v", changed)
	}
}

func fakeEndpoints(ports ...uint16) (ret []tailcfg.Endpoint) {
	for _, port := range ports {
		ret = append(ret, tailcfg.Endpoint{
			Addr: netip.AddrPortFrom(netip.Addr{}, port),
		})
	}
	return
}

func TestTsmpPing(t *testing.T) {
	hi := hostinfo.New()
	ni := tailcfg.NetInfo{LinkType: "wired"}
	hi.NetInfo = &ni

	k := key.NewMachine()
	opts := Options{
		ServerURL: "https://example.com",
		Hostinfo:  hi,
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return k, nil
		},
		Dialer: tsdial.NewDialer(netmon.NewStatic()),
	}

	c, err := NewDirect(opts)
	if err != nil {
		t.Fatal(err)
	}

	pingRes := &tailcfg.PingResponse{
		Type:     "TSMP",
		IP:       "123.456.7890",
		Err:      "",
		NodeName: "testnode",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body := new(ipnstate.PingResult)
		if err := json.NewDecoder(r.Body).Decode(body); err != nil {
			t.Fatal(err)
		}
		if pingRes.IP != body.IP {
			t.Fatalf("PingResult did not have the correct IP : got %v, expected : %v", body.IP, pingRes.IP)
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	now := time.Now()

	pr := &tailcfg.PingRequest{
		URL: ts.URL,
	}

	err = postPingResult(now, t.Logf, c.httpc, pr, pingRes)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodeBase36(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"abcd1234", []byte{0x0a, 0x4b, 0x1c, 0x2d, 0x3e}},
		{"1z141z", []byte{0x01, 0x23, 0x45, 0x67}},
	}

	for _, test := range tests {
		result, err := decodeBase36(test.input)
		if err != nil {
			t.Errorf("decodeBase36(%s) returned error: %v", test.input, err)
		}
		if !bytes.Equal(result, test.expected) {
			t.Errorf("decodeBase36(%s) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestVerifyHeadscaleHelperCert(t *testing.T) {
	// Generate a self-signed certificate for testing
	certPEM, keyPEM, err := generateSelfSignedCert("abcd1234.headscale-helper.com")
	if err != nil {
		t.Fatalf("failed to generate self-signed certificate: %v", err)
	}

	// Parse the certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Create a test server with the self-signed certificate
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, world!"))
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	ts.StartTLS()
	defer ts.Close()

	// Create a custom HTTP client with the verification function
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return verifyHeadscaleHelperCert(rawCerts, verifiedChains)
				},
			},
		},
	}

	// Make a request to the test server
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status code: got %v, expected %v", resp.StatusCode, http.StatusOK)
	}
}
