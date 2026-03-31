package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// --- Test helpers ---

func testKeyPair(t *testing.T) KeyPair {
	t.Helper()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

func testRootToken(t *testing.T, kp KeyPair) string {
	t.Helper()
	token, err := MintRootToken(kp.PrivateKey, AllCapabilities(), 1*time.Hour)
	if err != nil {
		t.Fatalf("MintRootToken: %v", err)
	}
	return token
}

func testValidator(t *testing.T, kp KeyPair) *TokenValidator {
	t.Helper()
	v := NewTokenValidator(kp.PublicKey)
	rootToken := testRootToken(t, kp)
	v.RegisterToken(rootToken, AllCapabilities())
	return v
}

// --- Key Management ---

func TestGenerateKeyPair(t *testing.T) {
	kp := testKeyPair(t)

	if len(kp.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("expected public key size %d, got %d", ed25519.PublicKeySize, len(kp.PublicKey))
	}
	if len(kp.PrivateKey) != ed25519.PrivateKeySize {
		t.Fatalf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(kp.PrivateKey))
	}

	// Public key should be derivable from private key.
	derived := kp.PrivateKey.Public().(ed25519.PublicKey)
	if !derived.Equal(kp.PublicKey) {
		t.Fatal("public key not derivable from private key")
	}

	// Two calls produce different keys.
	kp2 := testKeyPair(t)
	if kp.PublicKey.Equal(kp2.PublicKey) {
		t.Fatal("two GenerateKeyPair calls produced identical keys")
	}
}

func TestSaveLoadKeyPair(t *testing.T) {
	kp := testKeyPair(t)
	dir := t.TempDir()

	if err := SaveKeyPair(kp, dir); err != nil {
		t.Fatalf("SaveKeyPair: %v", err)
	}

	loaded, err := LoadKeyPair(dir)
	if err != nil {
		t.Fatalf("LoadKeyPair: %v", err)
	}

	if !kp.PublicKey.Equal(loaded.PublicKey) {
		t.Fatal("loaded public key does not match original")
	}
	if !kp.PrivateKey.Equal(loaded.PrivateKey) {
		t.Fatal("loaded private key does not match original")
	}
}

func TestSaveLoadPublicKey(t *testing.T) {
	kp := testKeyPair(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pub")

	if err := SavePublicKey(kp.PublicKey, path); err != nil {
		t.Fatalf("SavePublicKey: %v", err)
	}

	loaded, err := LoadPublicKey(path)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}

	if !kp.PublicKey.Equal(loaded) {
		t.Fatal("loaded public key does not match original")
	}
}

func TestSaveLoadToken(t *testing.T) {
	kp := testKeyPair(t)
	token := testRootToken(t, kp)
	dir := t.TempDir()

	if err := SaveToken(token, dir); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	loaded, err := LoadToken(dir)
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}

	if loaded != token {
		t.Fatal("loaded token does not match original")
	}

	// Verify whitespace is trimmed on load.
	padded := "\n  " + token + "  \n"
	if err := os.WriteFile(filepath.Join(dir, tokenFile), []byte(padded), 0600); err != nil {
		t.Fatalf("write padded token: %v", err)
	}
	loaded2, err := LoadToken(dir)
	if err != nil {
		t.Fatalf("LoadToken (padded): %v", err)
	}
	if loaded2 != token {
		t.Fatalf("whitespace not trimmed: got %q", loaded2)
	}
}

// --- Token Minting ---

func TestMintRootToken(t *testing.T) {
	kp := testKeyPair(t)
	token := testRootToken(t, kp)

	// Parse and inspect claims.
	claims := parseClaimsUnverified(t, token)

	kid := pubKeyToString(kp.PublicKey)
	if claims.Issuer != kid {
		t.Fatalf("expected iss=%s, got %s", kid, claims.Issuer)
	}

	aud, err := claims.GetAudience()
	if err != nil || len(aud) != 1 || aud[0] != kid {
		t.Fatalf("expected aud=[%s], got %v (err=%v)", kid, aud, err)
	}

	if claims.Subject != "claude-peers" {
		t.Fatalf("expected sub=claude-peers, got %s", claims.Subject)
	}

	if claims.Proof != "" {
		t.Fatalf("expected empty prf for root, got %q", claims.Proof)
	}

	if len(claims.Capabilities) != len(AllCapabilities()) {
		t.Fatalf("expected %d capabilities, got %d", len(AllCapabilities()), len(claims.Capabilities))
	}

	if claims.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set")
	}
}

func TestMintDelegatedToken(t *testing.T) {
	rootKP := testKeyPair(t)
	childKP := testKeyPair(t)
	rootToken := testRootToken(t, rootKP)

	childCaps := PeerSessionCapabilities()
	childToken, err := MintToken(rootKP.PrivateKey, childKP.PublicKey, childCaps, 30*time.Minute, rootToken)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	claims := parseClaimsUnverified(t, childToken)

	if claims.Proof != TokenHash(rootToken) {
		t.Fatal("prf should be hash of parent token")
	}

	if claims.Issuer != pubKeyToString(rootKP.PublicKey) {
		t.Fatal("iss should be parent's public key")
	}

	aud, _ := claims.GetAudience()
	if len(aud) != 1 || aud[0] != pubKeyToString(childKP.PublicKey) {
		t.Fatalf("aud should be child's public key, got %v", aud)
	}

	if len(claims.Capabilities) != len(childCaps) {
		t.Fatalf("expected %d caps, got %d", len(childCaps), len(claims.Capabilities))
	}
}

func TestMintToken_AttenuationRejectsEscalation(t *testing.T) {
	rootKP := testKeyPair(t)
	childKP := testKeyPair(t)

	// Parent has only peer/list.
	parentToken, err := MintRootToken(rootKP.PrivateKey, []Capability{{Resource: "peer/list"}}, 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Child requests memory/write which parent doesn't have.
	_, err = MintToken(rootKP.PrivateKey, childKP.PublicKey, []Capability{{Resource: "memory/write"}}, 30*time.Minute, parentToken)
	if err == nil {
		t.Fatal("expected error for capability escalation")
	}
	if !strings.Contains(err.Error(), "attenuation violation") {
		t.Fatalf("expected attenuation violation error, got: %v", err)
	}

	// Partial overlap: parent has peer/list + msg/send, child wants peer/list + memory/write.
	parentToken2, err := MintRootToken(rootKP.PrivateKey, []Capability{{Resource: "peer/list"}, {Resource: "msg/send"}}, 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, err = MintToken(rootKP.PrivateKey, childKP.PublicKey, []Capability{{Resource: "peer/list"}, {Resource: "memory/write"}}, 30*time.Minute, parentToken2)
	if err == nil {
		t.Fatal("expected error for partial overlap escalation")
	}
}

func TestMintToken_SubsetCapabilities(t *testing.T) {
	rootKP := testKeyPair(t)
	childKP := testKeyPair(t)

	// Parent has all, child gets peer/list only.
	rootToken := testRootToken(t, rootKP)
	_, err := MintToken(rootKP.PrivateKey, childKP.PublicKey, []Capability{{Resource: "peer/list"}}, 30*time.Minute, rootToken)
	if err != nil {
		t.Fatalf("subset should succeed: %v", err)
	}

	// Parent has all, child gets PeerSessionCapabilities.
	_, err = MintToken(rootKP.PrivateKey, childKP.PublicKey, PeerSessionCapabilities(), 30*time.Minute, rootToken)
	if err != nil {
		t.Fatalf("PeerSession subset should succeed: %v", err)
	}
}

func TestMintToken_EmptyCapabilities(t *testing.T) {
	rootKP := testKeyPair(t)
	childKP := testKeyPair(t)
	rootToken := testRootToken(t, rootKP)

	token, err := MintToken(rootKP.PrivateKey, childKP.PublicKey, []Capability{}, 30*time.Minute, rootToken)
	if err != nil {
		t.Fatalf("empty caps should succeed: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestTokenHash_Deterministic(t *testing.T) {
	kp := testKeyPair(t)
	token := testRootToken(t, kp)

	h1 := TokenHash(token)
	h2 := TokenHash(token)
	if h1 != h2 {
		t.Fatal("same token produced different hashes")
	}

	kp2 := testKeyPair(t)
	token2 := testRootToken(t, kp2)
	h3 := TokenHash(token2)
	if h1 == h3 {
		t.Fatal("different tokens produced same hash")
	}
}

// --- Validation ---

func TestValidate_ValidRootToken(t *testing.T) {
	kp := testKeyPair(t)
	token := testRootToken(t, kp)
	v := NewTokenValidator(kp.PublicKey)

	claims, err := v.Validate(token)
	if err != nil {
		t.Fatalf("validate root: %v", err)
	}
	if claims.Subject != "claude-peers" {
		t.Fatalf("unexpected subject: %s", claims.Subject)
	}
}

func TestValidate_ValidDelegatedToken(t *testing.T) {
	rootKP := testKeyPair(t)
	childKP := testKeyPair(t)
	rootToken := testRootToken(t, rootKP)

	v := NewTokenValidator(rootKP.PublicKey)
	// Validate root first so it's registered.
	if _, err := v.Validate(rootToken); err != nil {
		t.Fatalf("validate root: %v", err)
	}

	childCaps := PeerSessionCapabilities()
	childToken, err := MintToken(rootKP.PrivateKey, childKP.PublicKey, childCaps, 30*time.Minute, rootToken)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	claims, err := v.Validate(childToken)
	if err != nil {
		t.Fatalf("validate child: %v", err)
	}
	if len(claims.Capabilities) != len(childCaps) {
		t.Fatalf("expected %d caps, got %d", len(childCaps), len(claims.Capabilities))
	}
}

func TestValidate_ExpiredToken(t *testing.T) {
	kp := testKeyPair(t)
	// Mint with very short TTL, wait past it + leeway.
	token, err := MintRootToken(kp.PrivateKey, AllCapabilities(), 1*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	// Wait well past the 30s leeway.
	time.Sleep(50 * time.Millisecond)

	// We need to test expiry, but the 30s leeway means a 1ms token is still valid.
	// Instead, craft a token that expired 60s ago.
	token2, err := MintRootToken(kp.PrivateKey, AllCapabilities(), -60*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	v := NewTokenValidator(kp.PublicKey)
	_, err = v.Validate(token2)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected 'expired' in error, got: %v", err)
	}

	// The 1ms token should still pass within leeway.
	_, err = v.Validate(token)
	if err != nil {
		t.Fatalf("token within leeway should pass: %v", err)
	}
}

func TestValidate_ClockSkewTolerance(t *testing.T) {
	kp := testKeyPair(t)
	v := NewTokenValidator(kp.PublicKey)

	// Expired 20s ago -- within 30s leeway, should pass.
	token1, err := MintRootToken(kp.PrivateKey, AllCapabilities(), -20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Validate(token1); err != nil {
		t.Fatalf("expected 20s-expired token to pass within 30s leeway: %v", err)
	}

	// Expired 60s ago -- outside leeway, should fail.
	token2, err := MintRootToken(kp.PrivateKey, AllCapabilities(), -60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Validate(token2); err == nil {
		t.Fatal("expected 60s-expired token to fail")
	}
}

func TestValidate_BadSignature(t *testing.T) {
	kp := testKeyPair(t)
	token := testRootToken(t, kp)
	v := NewTokenValidator(kp.PublicKey)

	// Tamper with signature by flipping multiple characters in the middle of the sig.
	parts := strings.SplitN(token, ".", 3)
	sig := parts[2]
	// Flip several bytes in the middle of the signature to guarantee corruption.
	mid := len(sig) / 2
	corrupted := sig[:mid-2] + "XXXX" + sig[mid+2:]
	tampered := parts[0] + "." + parts[1] + "." + corrupted
	_, err := v.Validate(tampered)
	if err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestValidate_WrongRootKey(t *testing.T) {
	kpA := testKeyPair(t)
	kpB := testKeyPair(t)

	token := testRootToken(t, kpA)
	v := NewTokenValidator(kpB.PublicKey) // Anchored to B.

	_, err := v.Validate(token)
	if err == nil {
		t.Fatal("expected error for wrong root key")
	}
	if !strings.Contains(err.Error(), "root token issuer does not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_UnknownProof(t *testing.T) {
	rootKP := testKeyPair(t)
	childKP := testKeyPair(t)
	rootToken := testRootToken(t, rootKP)

	// Mint child but don't register root in validator.
	childToken, err := MintToken(rootKP.PrivateKey, childKP.PublicKey, PeerSessionCapabilities(), 30*time.Minute, rootToken)
	if err != nil {
		t.Fatal(err)
	}

	v := NewTokenValidator(rootKP.PublicKey)
	// Do NOT validate root first -- child's proof is unknown.
	_, err = v.Validate(childToken)
	if err == nil {
		t.Fatal("expected error for unknown proof")
	}
	if !strings.Contains(err.Error(), "unknown proof") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_EscalatedChild(t *testing.T) {
	rootKP := testKeyPair(t)
	childKP := testKeyPair(t)

	// Root with only peer/list.
	limitedRoot, err := MintRootToken(rootKP.PrivateKey, []Capability{{Resource: "peer/list"}}, 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	v := NewTokenValidator(rootKP.PublicKey)
	if _, err := v.Validate(limitedRoot); err != nil {
		t.Fatalf("validate limited root: %v", err)
	}

	// Manually craft child claiming memory/write (bypass MintToken's attenuation check).
	// We need to sign with rootKP to get a valid signature, but claim caps the parent doesn't have.
	claims := UCANClaims{
		Capabilities: []Capability{{Resource: "peer/list"}, {Resource: "memory/write"}},
		Proof:        TokenHash(limitedRoot),
	}
	claims.Issuer = pubKeyToString(rootKP.PublicKey)
	claims.Audience = []string{pubKeyToString(childKP.PublicKey)}
	claims.Subject = "claude-peers"
	now := time.Now()
	claims.IssuedAt = jwtNumericDate(now)
	claims.ExpiresAt = jwtNumericDate(now.Add(30 * time.Minute))

	escalated := signClaims(t, rootKP.PrivateKey, claims)

	_, err = v.Validate(escalated)
	if err == nil {
		t.Fatal("expected error for escalated child token")
	}
	if !strings.Contains(err.Error(), "chain violation") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_WrongSubject(t *testing.T) {
	kp := testKeyPair(t)
	kid := pubKeyToString(kp.PublicKey)

	claims := UCANClaims{
		Capabilities: AllCapabilities(),
		Proof:        "",
	}
	claims.Issuer = kid
	claims.Audience = []string{kid}
	claims.Subject = "wrong-subject"
	now := time.Now()
	claims.IssuedAt = jwtNumericDate(now)
	claims.ExpiresAt = jwtNumericDate(now.Add(1 * time.Hour))

	token := signClaims(t, kp.PrivateKey, claims)

	v := NewTokenValidator(kp.PublicKey)
	_, err := v.Validate(token)
	if err == nil {
		t.Fatal("expected error for wrong subject")
	}
	if !strings.Contains(err.Error(), "invalid subject") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_ChainOfThree(t *testing.T) {
	rootKP := testKeyPair(t)
	midKP := testKeyPair(t)
	leafKP := testKeyPair(t)

	rootToken := testRootToken(t, rootKP)
	v := NewTokenValidator(rootKP.PublicKey)

	// Validate root.
	if _, err := v.Validate(rootToken); err != nil {
		t.Fatalf("validate root: %v", err)
	}

	// Root -> middle: subset caps.
	midCaps := []Capability{{Resource: "peer/list"}, {Resource: "msg/send"}, {Resource: "events/read"}}
	midToken, err := MintToken(rootKP.PrivateKey, midKP.PublicKey, midCaps, 30*time.Minute, rootToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Validate(midToken); err != nil {
		t.Fatalf("validate middle: %v", err)
	}

	// Middle -> leaf: further subset.
	leafCaps := []Capability{{Resource: "peer/list"}}
	leafToken, err := MintToken(midKP.PrivateKey, leafKP.PublicKey, leafCaps, 15*time.Minute, midToken)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := v.Validate(leafToken)
	if err != nil {
		t.Fatalf("validate leaf: %v", err)
	}
	if len(claims.Capabilities) != 1 || claims.Capabilities[0].Resource != "peer/list" {
		t.Fatalf("leaf should only have peer/list, got %v", claims.Capabilities)
	}
}

func TestValidate_DelegationChainBreaks(t *testing.T) {
	rootKP := testKeyPair(t)
	midKP := testKeyPair(t)
	leafKP := testKeyPair(t)

	rootToken := testRootToken(t, rootKP)
	v := NewTokenValidator(rootKP.PublicKey)

	// Build chain normally.
	if _, err := v.Validate(rootToken); err != nil {
		t.Fatal(err)
	}
	midToken, err := MintToken(rootKP.PrivateKey, midKP.PublicKey, PeerSessionCapabilities(), 30*time.Minute, rootToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Validate(midToken); err != nil {
		t.Fatal(err)
	}
	leafToken, err := MintToken(midKP.PrivateKey, leafKP.PublicKey, []Capability{{Resource: "peer/list"}}, 15*time.Minute, midToken)
	if err != nil {
		t.Fatal(err)
	}

	// Create fresh validator with NO known tokens -- chain is broken.
	v2 := NewTokenValidator(rootKP.PublicKey)
	_, err = v2.Validate(leafToken)
	if err == nil {
		t.Fatal("expected error for broken chain")
	}
	if !strings.Contains(err.Error(), "unknown proof") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Capability Checking ---

func TestHasCapability(t *testing.T) {
	claims := &UCANClaims{
		Capabilities: []Capability{{Resource: "peer/list"}, {Resource: "msg/send"}},
	}

	if !HasCapability(claims, "peer/list") {
		t.Fatal("expected peer/list to be present")
	}
	if !HasCapability(claims, "msg/send") {
		t.Fatal("expected msg/send to be present")
	}
	if HasCapability(claims, "memory/write") {
		t.Fatal("expected memory/write to be absent")
	}
	if HasCapability(claims, "") {
		t.Fatal("expected empty string to be absent")
	}
}

func TestCapabilitySets(t *testing.T) {
	all := AllCapabilities()
	if len(all) != 12 {
		t.Fatalf("expected 12 AllCapabilities, got %d", len(all))
	}

	allSet := make(map[string]bool)
	for _, c := range all {
		allSet[c.Resource] = true
	}

	// PeerSession is a subset of All.
	for _, c := range PeerSessionCapabilities() {
		if !allSet[c.Resource] {
			t.Fatalf("PeerSessionCapabilities has %q not in AllCapabilities", c.Resource)
		}
	}

	// FleetRead is a subset of All.
	for _, c := range FleetReadCapabilities() {
		if !allSet[c.Resource] {
			t.Fatalf("FleetReadCapabilities has %q not in AllCapabilities", c.Resource)
		}
	}

	// FleetWrite includes memory/write.
	fwSet := make(map[string]bool)
	for _, c := range FleetWriteCapabilities() {
		fwSet[c.Resource] = true
	}
	if !fwSet["memory/write"] {
		t.Fatal("FleetWriteCapabilities missing memory/write")
	}

	// FleetRead does NOT include memory/write.
	frSet := make(map[string]bool)
	for _, c := range FleetReadCapabilities() {
		frSet[c.Resource] = true
	}
	if frSet["memory/write"] {
		t.Fatal("FleetReadCapabilities should not have memory/write")
	}

	// CLI includes msg/send.
	cliSet := make(map[string]bool)
	for _, c := range CLICapabilities() {
		cliSet[c.Resource] = true
	}
	if !cliSet["msg/send"] {
		t.Fatal("CLICapabilities missing msg/send")
	}
}

// --- Middleware ---

func TestUCANMiddleware_HealthBypass(t *testing.T) {
	kp := testKeyPair(t)
	v := testValidator(t, kp)

	handler := ucanMiddleware(v, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200 for /health, got %d", rec.Code)
	}
}

func TestUCANMiddleware_MissingHeader(t *testing.T) {
	kp := testKeyPair(t)
	v := testValidator(t, kp)

	handler := ucanMiddleware(v, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/some-endpoint", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "NO_AUTH") {
		t.Fatalf("expected NO_AUTH in body, got: %s", body)
	}
}

func TestUCANMiddleware_ValidToken(t *testing.T) {
	kp := testKeyPair(t)
	v := NewTokenValidator(kp.PublicKey)
	token := testRootToken(t, kp)

	var gotClaims *UCANClaims
	handler := ucanMiddleware(v, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = claimsFromContext(r.Context())
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if gotClaims == nil {
		t.Fatal("expected claims in context")
	}
	if gotClaims.Subject != "claude-peers" {
		t.Fatalf("unexpected subject in claims: %s", gotClaims.Subject)
	}
}

func TestUCANMiddleware_InvalidToken(t *testing.T) {
	kp := testKeyPair(t)
	v := testValidator(t, kp)

	handler := ucanMiddleware(v, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer garbage.token.here")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestUCANMiddleware_ExpiredToken(t *testing.T) {
	kp := testKeyPair(t)
	v := NewTokenValidator(kp.PublicKey)

	token, err := MintRootToken(kp.PrivateKey, AllCapabilities(), -60*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	handler := ucanMiddleware(v, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "TOKEN_EXPIRED") {
		t.Fatalf("expected TOKEN_EXPIRED in body, got: %s", body)
	}
}

func TestRequireCapability_Sufficient(t *testing.T) {
	kp := testKeyPair(t)
	v := NewTokenValidator(kp.PublicKey)
	token := testRootToken(t, kp)

	inner := requireCapability("peer/list", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})

	handler := ucanMiddleware(v, nil)(inner)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRequireCapability_Insufficient(t *testing.T) {
	kp := testKeyPair(t)
	childKP := testKeyPair(t)
	rootToken := testRootToken(t, kp)

	v := NewTokenValidator(kp.PublicKey)
	if _, err := v.Validate(rootToken); err != nil {
		t.Fatal(err)
	}

	// Child has only peer/list.
	childToken, err := MintToken(kp.PrivateKey, childKP.PublicKey, []Capability{{Resource: "peer/list"}}, 30*time.Minute, rootToken)
	if err != nil {
		t.Fatal(err)
	}

	inner := requireCapability("memory/write", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	handler := ucanMiddleware(v, nil)(inner)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+childToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 403 {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "MISSING_CAPABILITY") {
		t.Fatalf("expected MISSING_CAPABILITY in body, got: %s", body)
	}
}

// --- Integration ---

func TestBrokerWithUCAN_FullFlow(t *testing.T) {
	b := testBroker(t)

	rootKP := testKeyPair(t)
	childKP := testKeyPair(t)
	rootToken := testRootToken(t, rootKP)

	v := NewTokenValidator(rootKP.PublicKey)
	if _, err := v.Validate(rootToken); err != nil {
		t.Fatal(err)
	}

	// Peer session token (no memory/write).
	peerToken, err := MintToken(rootKP.PrivateKey, childKP.PublicKey, PeerSessionCapabilities(), 30*time.Minute, rootToken)
	if err != nil {
		t.Fatal(err)
	}

	// Build mux with UCAN middleware.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", requireCapability("peer/register", func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeBody[RegisterRequest](r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, b.register(req))
	}))
	mux.HandleFunc("POST /list-peers", requireCapability("peer/list", func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeBody[ListPeersRequest](r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, b.listPeers(req))
	}))
	mux.HandleFunc("POST /fleet-memory", requireCapability("memory/write", func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		b.setFleetMemory(string(data))
		writeJSON(w, map[string]bool{"ok": true})
	}))

	srv := httptest.NewServer(ucanMiddleware(v, nil)(mux))
	defer srv.Close()

	// POST /register with peer token -> 200.
	regBody, _ := json.Marshal(RegisterRequest{PID: 1, Machine: "test", CWD: "/tmp"})
	resp := doRequest(t, srv, "POST", "/register", peerToken, regBody)
	if resp.StatusCode != 200 {
		t.Fatalf("register: expected 200, got %d", resp.StatusCode)
	}

	// POST /list-peers with peer token -> 200.
	listBody, _ := json.Marshal(ListPeersRequest{Scope: "all"})
	resp = doRequest(t, srv, "POST", "/list-peers", peerToken, listBody)
	if resp.StatusCode != 200 {
		t.Fatalf("list-peers: expected 200, got %d", resp.StatusCode)
	}

	// POST /fleet-memory with peer token -> 200 (peer-session now has memory/write).
	resp = doRequest(t, srv, "POST", "/fleet-memory", peerToken, []byte("test data"))
	if resp.StatusCode != 200 {
		t.Fatalf("fleet-memory: expected 200, got %d", resp.StatusCode)
	}
}

func TestBrokerWithUCAN_FleetWriteCanWriteMemory(t *testing.T) {
	b := testBroker(t)

	rootKP := testKeyPair(t)
	childKP := testKeyPair(t)
	rootToken := testRootToken(t, rootKP)

	v := NewTokenValidator(rootKP.PublicKey)
	if _, err := v.Validate(rootToken); err != nil {
		t.Fatal(err)
	}

	fwToken, err := MintToken(rootKP.PrivateKey, childKP.PublicKey, FleetWriteCapabilities(), 30*time.Minute, rootToken)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /fleet-memory", requireCapability("memory/write", func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		b.setFleetMemory(string(data))
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("GET /fleet-memory", requireCapability("memory/read", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(b.getFleetMemory()))
	}))

	srv := httptest.NewServer(ucanMiddleware(v, nil)(mux))
	defer srv.Close()

	// POST fleet-memory -> 200.
	resp := doRequest(t, srv, "POST", "/fleet-memory", fwToken, []byte("fleet memory content"))
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("write fleet-memory: expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	// GET fleet-memory -> 200.
	resp = doRequest(t, srv, "GET", "/fleet-memory", fwToken, nil)
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("read fleet-memory: expected 200, got %d: %s", resp.StatusCode, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "fleet memory content" {
		t.Fatalf("expected 'fleet memory content', got %q", string(body))
	}
}

// --- Internal test helpers ---

func parseClaimsUnverified(t *testing.T, tokenStr string) *UCANClaims {
	t.Helper()
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	claims := &UCANClaims{}
	_, _, err := parser.ParseUnverified(tokenStr, claims)
	if err != nil {
		t.Fatalf("parse claims: %v", err)
	}
	return claims
}

func jwtNumericDate(t time.Time) *jwt.NumericDate {
	return jwt.NewNumericDate(t)
}

func signClaims(t *testing.T, key ed25519.PrivateKey, claims UCANClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	s, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign claims: %v", err)
	}
	return s
}

func doRequest(t *testing.T, srv *httptest.Server, method, path, token string, body []byte) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}
