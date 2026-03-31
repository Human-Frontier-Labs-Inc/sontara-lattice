package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
)

type contextKey string

const claimsContextKey contextKey = "ucan-claims"

// checkIPBinding logs a warning if the source IP doesn't match the
// expected IP for the machine named in the token claims.
// Reads expected IPs from the "machine_ips" config field.
// Soft enforcement only -- never blocks.
func checkIPBinding(sourceIP, machineName string) {
	if machineName == "" {
		return
	}
	machineIPs := loadMachineIPs()
	expected, ok := machineIPs[machineName]
	if !ok {
		// Unknown machine -- nothing to check.
		return
	}
	for _, ip := range expected {
		if sourceIP == ip {
			return
		}
	}
	log.Printf("[auth] IP mismatch: machine=%s token_machine=%s source_ip=%s expected=%v",
		machineName, machineName, sourceIP, expected)
}

func ucanMiddleware(validator *TokenValidator, health healthChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" || r.URL.Path == "/challenge" || r.URL.Path == "/refresh-token" {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeAuthError(w, http.StatusUnauthorized, "missing authorization header", "NO_AUTH")
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenStr == authHeader {
				writeAuthError(w, http.StatusUnauthorized, "missing authorization header", "NO_AUTH")
				return
			}

			claims, err := validator.Validate(tokenStr)
			if err != nil {
				msg := err.Error()
				switch {
				case strings.Contains(msg, "expired"):
					writeAuthError(w, http.StatusUnauthorized, "token expired", "TOKEN_EXPIRED")
				case strings.Contains(msg, "proof") || strings.Contains(msg, "chain"):
					writeAuthError(w, http.StatusUnauthorized, "invalid delegation chain", "BAD_PROOF")
				default:
					writeAuthError(w, http.StatusUnauthorized, msg, "INVALID_TOKEN")
				}
				return
			}

			// Check if the machine is quarantined.
			if health != nil && claims.MachineName != "" {
				h := health.getMachineHealth(claims.MachineName)
				if h != nil && h.Status == "quarantined" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]string{
						"error": "machine quarantined: " + h.LastEventDesc,
						"code":  "QUARANTINED",
					})
					return
				}
			}

			// Log source IP for every authenticated request.
			sourceIP := r.RemoteAddr
			if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				sourceIP = host
			}
			peerIdentity := ""
			if len(claims.Audience) > 0 {
				peerIdentity = claims.Audience[0]
			}
			log.Printf("[auth] authenticated request: path=%s ip=%s peer=%s machine=%s",
				r.URL.Path, sourceIP, peerIdentity, claims.MachineName)

			// Soft IP-binding check: log a warning if source IP doesn't match expected machine IP.
			checkIPBinding(sourceIP, claims.MachineName)

			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func requireCapability(resource string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromContext(r.Context())
		if claims == nil || !HasCapability(claims, resource) {
			writeAuthError(w, http.StatusForbidden, "insufficient capability: "+resource, "MISSING_CAPABILITY")
			return
		}
		handler(w, r)
	}
}

func claimsFromContext(ctx context.Context) *UCANClaims {
	claims, _ := ctx.Value(claimsContextKey).(*UCANClaims)
	return claims
}

func writeAuthError(w http.ResponseWriter, status int, message string, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
		"code":  code,
	})
}
