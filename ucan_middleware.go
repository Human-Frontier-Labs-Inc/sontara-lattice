package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type contextKey string

const claimsContextKey contextKey = "ucan-claims"

func ucanMiddleware(validator *TokenValidator, health healthChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
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
