package goclilogin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/oauth2"
)

// handlerTransport answers a request from a handler in the same goroutine, with
// no network, so a synctest bubble can advance its clock past each poll interval.
type handlerTransport struct{ handler http.Handler }

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

// A provider rate-limiting its token endpoint answers the poll of a login still
// waiting for approval with one of these. Each has to widen the interval by five
// seconds and keep the poll going, rather than end the login.
func TestPollForApproval_WaitsThroughAnAnswerAskingItToBackOff(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{name: "slow_down", status: http.StatusBadRequest, contentType: "application/json", body: `{"error":"slow_down"}`},
		{
			name:        "temporarily_unavailable",
			status:      http.StatusServiceUnavailable,
			contentType: "application/json",
			body:        `{"error":"temporarily_unavailable"}`,
		},
		{name: "HTTP 429 from a proxy", status: http.StatusTooManyRequests, contentType: "text/plain", body: "Too Many Requests"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var polls []time.Time
				tokenEndpoint := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					polls = append(polls, time.Now())
					switch len(polls) {
					case 1:
						w.Header().Set("Content-Type", tt.contentType)
						w.WriteHeader(tt.status)
						_, _ = io.WriteString(w, tt.body)
					case 2:
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusBadRequest)
						_, _ = io.WriteString(w, `{"error":"authorization_pending"}`)
					default:
						w.Header().Set("Content-Type", "application/json")
						_, _ = io.WriteString(w, `{"access_token":"AT","token_type":"Bearer","expires_in":300}`)
					}
				})
				ctx := context.WithValue(t.Context(), oauth2.HTTPClient,
					&http.Client{Transport: handlerTransport{handler: tokenEndpoint}})
				cfg := &oauth2.Config{
					ClientID: "myapp-cli-workstation",
					Endpoint: oauth2.Endpoint{TokenURL: "https://idp.test/token", AuthStyle: oauth2.AuthStyleInParams},
				}
				deviceAuth := &oauth2.DeviceAuthResponse{
					DeviceCode: "device-code",
					Interval:   5,
					Expiry:     time.Now().Add(10 * time.Minute),
				}

				token, err := pollForApproval(ctx, cfg, deviceAuth)
				if err != nil {
					t.Fatalf("the login ended on the first answer: %v", err)
				}
				if token.AccessToken != "AT" || len(polls) != 3 {
					t.Fatalf("token = %+v after %d polls, want AT after 3", token, len(polls))
				}
				for i, want := range []time.Duration{10 * time.Second, 10 * time.Second} {
					if gap := polls[i+1].Sub(polls[i]); gap != want {
						t.Errorf("gap before poll %d = %s, want %s", i+2, gap, want)
					}
				}
			})
		})
	}
}
