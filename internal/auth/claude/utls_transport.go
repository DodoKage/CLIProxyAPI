// Package claude provides authentication functionality for Anthropic's Claude API.
// This file implements a custom HTTP transport using utls to replicate the exact
// TLS fingerprint of Claude Code CLI (OpenSSL 3.x / Python httpx).
package claude

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	tls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// utlsRoundTripper implements http.RoundTripper using utls to replicate the
// exact TLS fingerprint of the Claude Code CLI (OpenSSL 3.x, 52 cipher suites,
// no GREASE, ML-KEM-768 key share).
//
// Since the fingerprint has no ALPN extension (matching real Claude Code CLI),
// servers typically respond with HTTP/1.1. The transport auto-detects the
// negotiated protocol and uses h2 or HTTP/1.1 accordingly.
type utlsRoundTripper struct {
	mu      sync.Mutex
	h2Conns map[string]*http2.ClientConn
	pending map[string]*sync.Cond
	dialer  proxy.Dialer
}

func newUtlsRoundTripper(cfg *config.SDKConfig) *utlsRoundTripper {
	var dialer proxy.Dialer = proxy.Direct
	if cfg != nil {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(cfg.ProxyURL)
		if errBuild != nil {
			log.Errorf("failed to configure proxy dialer for %q: %v", cfg.ProxyURL, errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}
	return &utlsRoundTripper{
		h2Conns: make(map[string]*http2.ClientConn),
		pending: make(map[string]*sync.Cond),
		dialer:  dialer,
	}
}

// claudeCodeClientHelloSpec returns a ClientHelloSpec that exactly replicates
// the TLS fingerprint of Claude Code CLI (Python httpx + OpenSSL 3.x).
// Characteristics: 52 cipher suites, no GREASE, OpenSSL extension ordering,
// ML-KEM-768 + X25519 dual key shares, 26 signature algorithms.
func claudeCodeClientHelloSpec() tls.ClientHelloSpec {
	return tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS12,
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			// TLS 1.3 suites (1302 first — OpenSSL 3.x default ordering)
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			// TLS 1.2 ECDHE/DHE suites
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			0x009e, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
			0xc027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
			0x0067, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
			0xc028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
			0x006b, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
			0x00a3, // TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
			0x009f, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			0xccaa, // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
			0xc0ad, // TLS_ECDHE_ECDSA_WITH_AES_256_CCM
			0xc09f, // TLS_DHE_RSA_WITH_AES_256_CCM
			0xc05d, // TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384
			0xc061, // TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384
			0xc057, // TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384
			0xc053, // TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384
			0x00a2, // TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
			0xc0ac, // TLS_ECDHE_ECDSA_WITH_AES_128_CCM
			0xc09e, // TLS_DHE_RSA_WITH_AES_128_CCM
			0xc05c, // TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
			0xc060, // TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256
			0xc056, // TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256
			0xc052, // TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256
			0xc024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
			0x006a, // TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
			0xc023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
			0x0040, // TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
			0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
			0x0038, // TLS_DHE_DSS_WITH_AES_256_CBC_SHA
			0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
			0x0032, // TLS_DHE_DSS_WITH_AES_128_CBC_SHA
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			0xc09d, // TLS_RSA_WITH_AES_256_CCM
			0xc051, // TLS_RSA_WITH_ARIA_256_GCM_SHA384
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			0xc09c, // TLS_RSA_WITH_AES_128_CCM
			0xc050, // TLS_RSA_WITH_ARIA_128_GCM_SHA256
			0x003d, // TLS_RSA_WITH_AES_256_CBC_SHA256
			0x003c, // TLS_RSA_WITH_AES_128_CBC_SHA256
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
		CompressionMethods: []byte{0x00},
		Extensions: []tls.TLSExtension{
			// OpenSSL 3.x extension ordering: renegotiation_info first
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateNever},
			&tls.SNIExtension{},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0, 1, 2}},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.X25519MLKEM768, // ML-KEM-768 post-quantum (0x11ec)
				tls.X25519,
				tls.CurveP256,
				tls.CurveID(30), // X448
				tls.CurveP384,
				tls.CurveP521,
				tls.CurveID(0x0100), // ffdhe2048
				tls.CurveID(0x0101), // ffdhe3072
			}},
			&tls.SessionTicketExtension{},
			&tls.GenericExtension{Id: 22}, // encrypt_then_mac
			&tls.ExtendedMasterSecretExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				0x0905, 0x0906, 0x0904, // Unknown (not in utls dict; present in OpenSSL 3.x)
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.Ed25519,
				0x0808,                 // ed448
				0x081a, 0x081b, 0x081c, // Brainpool ECDSA TLS 1.3 schemes
				0x0809, 0x080a, 0x080b, // rsa_pss_pss_sha256/384/512
				tls.PSSWithSHA256, // rsa_pss_rsae_sha256 (0x0804)
				tls.PSSWithSHA384, // rsa_pss_rsae_sha384 (0x0805)
				tls.PSSWithSHA512, // rsa_pss_rsae_sha512 (0x0806)
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				0x0303, // SHA224 ECDSA
				0x0301, // SHA224 RSA
				0x0302, // SHA224 DSA
				0x0402, // SHA256 DSA
				0x0502, // SHA384 DSA
				0x0602, // SHA512 DSA
			}},
			&tls.SupportedVersionsExtension{Versions: []uint16{
				tls.VersionTLS13,
				tls.VersionTLS12,
			}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.X25519MLKEM768},
				{Group: tls.X25519},
			}},
		},
	}
}

// dialTLS establishes a TLS connection with the Claude Code CLI fingerprint.
func (t *utlsRoundTripper) dialTLS(host, addr string) (*tls.UConn, error) {
	conn, err := t.dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{ServerName: host}
	tlsConn := tls.UClient(conn, tlsConfig, tls.HelloCustom)
	spec := claudeCodeClientHelloSpec()
	if err := tlsConn.ApplyPreset(&spec); err != nil {
		conn.Close()
		return nil, err
	}
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// h1RoundTrip performs a single HTTP/1.1 round-trip over a pre-dialed TLS conn.
func h1RoundTrip(conn net.Conn, req *http.Request) (*http.Response, error) {
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("writing request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading response: %w", err)
	}
	return resp, nil
}

// utlsH1Transport wraps utlsRoundTripper to handle protocol negotiation.
type utlsH1Transport struct {
	rt *utlsRoundTripper
}

func (t *utlsH1Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	addr := req.URL.Host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	// Try cached h2 connection first.
	t.rt.mu.Lock()
	if h2Conn, ok := t.rt.h2Conns[host]; ok && h2Conn.CanTakeNewRequest() {
		t.rt.mu.Unlock()
		resp, err := h2Conn.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		t.rt.mu.Lock()
		delete(t.rt.h2Conns, host)
		t.rt.mu.Unlock()
	} else {
		t.rt.mu.Unlock()
	}

	tlsConn, err := t.rt.dialTLS(host, addr)
	if err != nil {
		return nil, err
	}

	proto := tlsConn.ConnectionState().NegotiatedProtocol
	if proto == "h2" {
		tr := &http2.Transport{}
		h2Conn, err := tr.NewClientConn(tlsConn)
		if err != nil {
			tlsConn.Close()
			return nil, err
		}
		t.rt.mu.Lock()
		t.rt.h2Conns[host] = h2Conn
		t.rt.mu.Unlock()
		return h2Conn.RoundTrip(req)
	}

	// HTTP/1.1: write request and read response over the TLS conn directly.
	return h1RoundTrip(tlsConn, req)
}

// NewAnthropicHttpClient creates an HTTP client that replicates the TLS
// fingerprint of Claude Code CLI for Anthropic API requests.
// It auto-detects the negotiated protocol (h2 vs HTTP/1.1) after handshake.
func NewAnthropicHttpClient(cfg *config.SDKConfig) *http.Client {
	rt := newUtlsRoundTripper(cfg)
	return &http.Client{
		Transport: &utlsH1Transport{rt: rt},
	}
}
