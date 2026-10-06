package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		wantKey       string
		wantErr       error
		wantErrString string
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey secret-token-12345"},
			},
			wantKey: "secret-token-12345",
		},
		{
			name:    "Missing Authorization Header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Empty Authorization Value",
			headers: http.Header{
				"Authorization": []string{""},
			},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed - Wrong Authentication Prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer secret-token-12345"},
			},
			wantKey:       "",
			wantErrString: "malformed authorization header",
		},
		{
			name: "Malformed - Missing Token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:       "",
			wantErrString: "malformed authorization header",
		},
		{
			name: "Malformed - Missing Space Separator",
			headers: http.Header{
				"Authorization": []string{"ApiKey12345"},
			},
			wantKey:       "",
			wantErrString: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
			} else if tt.wantErrString != "" {
				if err == nil || err.Error() != tt.wantErrString {
					t.Fatalf("expected error message %q, got %v", tt.wantErrString, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if gotKey != tt.wantKey {
				t.Errorf("got key %q, want %q", gotKey, tt.wantKey)
			}
		})
	}
}
