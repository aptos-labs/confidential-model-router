//go:build routertest

// Copyright 2026 Aptos Labs. Added to tinfoilsh/confidential-model-router on 2026-09-11.
// Licensed under the GNU Affero General Public License v3, like the rest of this program.

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-model-router/config"
	"github.com/tinfoilsh/confidential-model-router/manager"
	"github.com/tinfoilsh/confidential-model-router/ratelimit"
)

func TestVideoRouterRoutingAndBinaryResponse(t *testing.T) {
	// Exercise two configured names rather than accidentally passing through a
	// default/hardcoded selector. The response spans multiple proxy copy buffers.
	binary := make([]byte, 128*1024)
	for i := range binary {
		binary[i] = byte(i)
	}
	for _, model := range []string{videoTestModel, "second-configured-fixture"} {
		for _, responseType := range []string{"video/mp4", "application/octet-stream"} {
			for _, chunked := range []bool{false, true} {
				t.Run(model+"/"+responseType+"/chunked="+strconv.FormatBool(chunked), func(t *testing.T) {
					body, _ := videoTestForm(t, model)
					contentType := `Multipart/Form-Data; charset=utf-8; boundary="video-test-boundary"`
					r := videoTestRequest(body, contentType)
					if chunked {
						r.ContentLength = -1
						r.TransferEncoding = []string{"chunked"}
					}
					r.URL.RawQuery = "trace=fixture"
					// A conflicting configured subdomain must never override the form.
					r.Host = "host-decoy." + *domain
					r.Header.Set("X-Forwarded-Host", "host-decoy."+*domain)
					r.Header.Set("Forwarded", "host=host-decoy."+*domain)
					r.Header.Set(manager.UsageMetricsRequestHeader, "true")
					wantLength := r.ContentLength
					wantAuth := r.Header.Get("Authorization")
					calls := 0
					backends := map[string]http.Handler{}
					for _, name := range []string{videoTestModel, "second-configured-fixture", "host-decoy"} {
						backends[name] = http.HandlerFunc(func(w http.ResponseWriter, upstream *http.Request) {
							calls++
							if name != model {
								t.Errorf("selected %q, want %q", name, model)
							}
							if upstream.Method != http.MethodPost || upstream.URL.RequestURI() != "/v1/videos/sync?trace=fixture" {
								t.Errorf("method/path changed: %s %s", upstream.Method, upstream.URL.RequestURI())
							}
							got, err := io.ReadAll(upstream.Body)
							if err != nil || !bytes.Equal(got, body) {
								t.Errorf("upstream multipart changed: %v", err)
							}
							if upstream.Header.Get("Content-Type") != contentType || upstream.Header.Get("Authorization") != wantAuth {
								t.Error("upstream Content-Type or Authorization changed")
							}
							if upstream.ContentLength != wantLength {
								t.Errorf("ContentLength=%d, want %d", upstream.ContentLength, wantLength)
							}
							w.Header().Set("Content-Type", responseType)
							w.Header().Set("Content-Length", strconv.Itoa(len(binary)))
							w.Header().Set("Content-Disposition", `attachment; filename="result.mp4"`)
							w.Header().Set("X-Request-Id", "fixture-response")
							w.WriteHeader(http.StatusOK)
							if _, err := w.Write(binary); err != nil {
								t.Errorf("write binary response: %v", err)
							}
						})
					}
					rec := httptest.NewRecorder()
					newRouterHandler(manager.NewVideoRouterTestManager(backends), nil).ServeHTTP(rec, r)
					if calls != 1 || rec.Code != http.StatusOK {
						t.Fatalf("calls=%d status=%d", calls, rec.Code)
					}
					if !bytes.Equal(rec.Body.Bytes(), binary) {
						t.Fatal("binary response bytes changed")
					}
					for key, want := range map[string]string{
						"Content-Type":        responseType,
						"Content-Length":      strconv.Itoa(len(binary)),
						"Content-Disposition": `attachment; filename="result.mp4"`,
						"X-Request-Id":        "fixture-response",
						"Tinfoil-Enclave":     model + ".test.invalid",
						sourceOfferHeader:     correspondingSourceURL(),
						licenseHeader:         licenseID,
					} {
						if got := rec.Header().Get(key); got != want {
							t.Errorf("response %s=%q, want %q", key, got, want)
						}
					}
				})
			}
		}
	}
}

func assertVideoRouterError(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status=%d, want %d: %s", rec.Code, status, rec.Body.String())
	}
	var body struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("non-JSON error: %v", err)
	}
	if rec.Header().Get("Content-Type") != "application/json" || body.Error.Message == "" || body.Error.Type != manager.ErrTypeInvalidRequest {
		t.Fatalf("not an OpenAI-style invalid request error: %s", rec.Body.String())
	}
}

func TestVideoRouterUnknownModel(t *testing.T) {
	calls := 0
	em := manager.NewVideoRouterTestManager(map[string]http.Handler{
		videoTestModel: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }),
	})
	body, contentType := videoTestForm(t, "unknown-fixture")
	r := videoTestRequest(body, contentType)
	r.Header.Set("X-Forwarded-Host", videoTestModel+"."+*domain)
	rec := httptest.NewRecorder()
	newRouterHandler(em, nil).ServeHTTP(rec, r)
	assertVideoRouterError(t, rec, http.StatusNotFound)
	if calls != 0 {
		t.Fatal("unknown model fell back to a configured backend")
	}
}

func TestVideoRouterInvalidRequests(t *testing.T) {
	valid, contentType := videoTestForm(t, videoTestModel)
	missing, _ := videoTestForm(t)
	blank, _ := videoTestForm(t, " \t")
	duplicate, _ := videoTestForm(t, videoTestModel, "another-fixture")
	longModel, _ := videoTestForm(t, strings.Repeat("m", 257))
	manyParts, manyPartsType := videoTestParts(t, 129, 0)
	for _, tc := range []struct {
		name        string
		body        []byte
		contentType string
		method      string
		status      int
	}{
		{"missing model", missing, contentType, http.MethodPost, http.StatusBadRequest},
		{"blank model", blank, contentType, http.MethodPost, http.StatusBadRequest},
		{"duplicate model", duplicate, contentType, http.MethodPost, http.StatusBadRequest},
		{"257-byte model", longModel, contentType, http.MethodPost, http.StatusBadRequest},
		{"129 parts", manyParts, manyPartsType, http.MethodPost, http.StatusBadRequest},
		{"file model", bytes.Replace(valid, []byte(`name="model"`), []byte(`name="model"; filename="selector.txt"`), 1), contentType, http.MethodPost, http.StatusBadRequest},
		{"truncated after model", valid[:len(valid)-32], contentType, http.MethodPost, http.StatusBadRequest},
		{"json", []byte(`{"model":"configured-video-fixture"}`), "application/json", http.MethodPost, http.StatusUnsupportedMediaType},
		{"missing media type", valid, "", http.MethodPost, http.StatusUnsupportedMediaType},
		{"missing boundary", valid, "multipart/form-data", http.MethodPost, http.StatusBadRequest},
		{"wrong method", valid, contentType, http.MethodGet, http.StatusMethodNotAllowed},
	} {
		for _, subdomain := range []bool{false, true} {
			t.Run(tc.name+"/subdomain="+strconv.FormatBool(subdomain), func(t *testing.T) {
				r := videoTestRequest(tc.body, tc.contentType)
				r.Method = tc.method
				if subdomain {
					r.Header.Set("X-Forwarded-Host", videoTestModel+"."+*domain)
				}
				rec := httptest.NewRecorder()
				// nil manager proves validation returns before model lookup.
				newRouterHandler(nil, nil).ServeHTTP(rec, r)
				assertVideoRouterError(t, rec, tc.status)
				if tc.status == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != http.MethodPost {
					t.Fatal("405 response must advertise Allow: POST")
				}
			})
		}
	}
}

// An allocation-free source for a real unknown-length 64 MiB overflow. The
// parser still buffers only up to MaxBytesReader's bound; do not t.Parallel this.
type videoZeroReader struct{}

func (videoZeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestVideoRouterOversizedMultipart(t *testing.T) {
	body, contentType := videoTestForm(t, videoTestModel)
	t.Run("known length", func(t *testing.T) {
		r := videoTestRequest(body, contentType)
		r.ContentLength = maxRequestBodySize + 1
		rec := httptest.NewRecorder()
		newRouterHandler(nil, nil).ServeHTTP(rec, r)
		assertVideoRouterError(t, rec, http.StatusRequestEntityTooLarge)
		remaining, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(remaining, body) {
			t.Fatal("known oversized body should not be read")
		}
	})
	t.Run("unknown length", func(t *testing.T) {
		// Valid selector followed by a file that exceeds the limit. This must
		// not succeed just because the selector appears before the overflow.
		prefix := "--large-form\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n" + videoTestModel + "\r\n--large-form\r\nContent-Disposition: form-data; name=\"image\"; filename=\"large.bin\"\r\n\r\n"
		r := httptest.NewRequest(http.MethodPost, "/v1/videos/sync", io.MultiReader(
			strings.NewReader(prefix), io.LimitReader(videoZeroReader{}, maxRequestBodySize), strings.NewReader("\r\n--large-form--\r\n"),
		))
		r.ContentLength = -1
		r.TransferEncoding = []string{"chunked"}
		r.Header.Set("Content-Type", "multipart/form-data; boundary=large-form")
		rec := httptest.NewRecorder()
		newRouterHandler(nil, nil).ServeHTTP(rec, r)
		assertVideoRouterError(t, rec, http.StatusRequestEntityTooLarge)
	})
}

func TestVideoRouterOversizedWrongMethod(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		for _, knownLength := range []bool{true, false} {
			t.Run(method+"/knownLength="+strconv.FormatBool(knownLength), func(t *testing.T) {
				// A real oversized body, without allocating or consuming it.
				body := &io.LimitedReader{R: videoZeroReader{}, N: maxRequestBodySize + 1}
				r := httptest.NewRequest(method, "/v1/videos/sync?trace=fixture", body)
				if knownLength {
					r.ContentLength = body.N
				} else {
					r.ContentLength = -1
					r.TransferEncoding = []string{"chunked"}
				}
				rec := httptest.NewRecorder()
				newRouterHandler(nil, nil).ServeHTTP(rec, r)
				assertVideoRouterError(t, rec, http.StatusMethodNotAllowed)
				if rec.Header().Get("Allow") != http.MethodPost {
					t.Fatal("405 response must advertise Allow: POST")
				}
				if body.N != maxRequestBodySize+1 {
					t.Fatal("wrong-method body was read")
				}
			})
		}
	}
}

func TestVideoRouterOtherRouteBodyLimitsUnchanged(t *testing.T) {
	for _, path := range []string{"/v1/videos/sync/", "/v1/videos/sync/extra", "/v1/chat/completions", "/v1/responses", "/v1/audio/transcriptions"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(method+path, func(t *testing.T) {
				r := httptest.NewRequest(method, path, strings.NewReader("oversized"))
				r.ContentLength = maxRequestBodySize + 1
				rec := httptest.NewRecorder()
				newRouterHandler(nil, nil).ServeHTTP(rec, r)
				assertVideoRouterError(t, rec, http.StatusRequestEntityTooLarge)
				if rec.Header().Get("Allow") != "" {
					t.Fatal("video method guard matched another endpoint")
				}
			})
		}
	}
}

func TestVideoRouterJSONChatUnaffected(t *testing.T) {
	oldSalt := *cacheSaltEnabled
	*cacheSaltEnabled = false
	t.Cleanup(func() { *cacheSaltEnabled = oldSalt })
	const chatModel = "configured-chat-fixture"
	const reply = `{"choices":[{"message":{"role":"assistant","content":"hello"}}]}`
	calls := 0
	em := manager.NewVideoRouterTestManager(map[string]http.Handler{
		chatModel: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
				t.Errorf("method/path changed: %s %s", r.Method, r.URL.Path)
			}
			if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "Bearer chat-test-only-token" {
				t.Error("chat request headers changed")
			}
			var got map[string]any
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Errorf("decode upstream chat: %v", err)
			}
			want := map[string]any{"model": chatModel, "messages": []any{map[string]any{"role": "user", "content": "hello"}}, "stream": false}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("chat routing/sanitization changed: got=%v want=%v", got, want)
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, reply)
		}),
		videoTestModel: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("chat selected video fixture") }),
	})
	body := `{"model":"` + chatModel + `","messages":[{"role":"user","content":"hello"}],"stream":false,"priority":-999,"cache_salt":"untrusted"}`
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer chat-test-only-token")
	rec := httptest.NewRecorder()
	newRouterHandler(em, nil).ServeHTTP(rec, r)
	if calls != 1 || rec.Code != http.StatusOK || rec.Body.String() != reply {
		t.Fatalf("chat calls=%d status=%d body=%s", calls, rec.Code, rec.Body.String())
	}
}

func TestVideoRouterRateLimitAdmission(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.RateLimitConfig
	}{
		{"hard", config.RateLimitConfig{HardMaxRequestsPerMinute: 2}},
		{"soft fails closed", config.RateLimitConfig{MaxRequestsPerMinute: 2, HardMaxRequestsPerMinute: 10}},
		{"soft only fails closed", config.RateLimitConfig{MaxRequestsPerMinute: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A fractional second proves Retry-After rounds up, not down.
			now := time.Date(2026, 1, 1, 12, 0, 15, 500000000, time.UTC)
			const otherModel = "other-video-limit-fixture"
			const contentType = `Multipart/Form-Data; charset=utf-8; boundary="video-test-boundary"`
			calls := 0
			backends := map[string]http.Handler{}
			for _, name := range []string{videoTestModel, otherModel} {
				wantBody, _ := videoTestForm(t, name)
				backends[name] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					got, err := io.ReadAll(r.Body)
					if err != nil || !bytes.Equal(got, wantBody) {
						t.Errorf("admitted multipart changed: %v", err)
					}
					if r.Header.Get("Content-Type") != contentType || r.ContentLength != int64(len(wantBody)) {
						t.Error("admitted multipart headers changed")
					}
					if auth := r.Header.Get("Authorization"); auth != "Bearer key-a-fixture" && auth != "Bearer key-b-fixture" {
						t.Error("admitted authorization changed")
					}
					w.Header().Set("Content-Type", "video/mp4")
					w.Write([]byte{0, 1, 0xff})
				})
			}
			em := manager.NewVideoRouterTestManager(backends, ratelimit.WithNowFunc(func() time.Time { return now }))
			for name := range backends {
				model, _ := em.GetModel(name)
				model.RateLimit = &tc.cfg
			}
			handler := newRouterHandler(em, nil)
			for i, req := range []struct {
				key, model string
				status     int
			}{
				{"key-a-fixture", videoTestModel, http.StatusOK},
				{"key-a-fixture", videoTestModel, http.StatusTooManyRequests},
				{"key-a-fixture", videoTestModel, http.StatusTooManyRequests},
				{"key-b-fixture", videoTestModel, http.StatusOK},
				{"key-a-fixture", otherModel, http.StatusOK},
				{"key-b-fixture", otherModel, http.StatusOK},
				{"key-b-fixture", videoTestModel, http.StatusTooManyRequests},
				{"key-a-fixture", otherModel, http.StatusTooManyRequests},
				{"key-b-fixture", otherModel, http.StatusTooManyRequests},
			} {
				body, _ := videoTestForm(t, req.model)
				r := videoTestRequest(body, contentType)
				r.Header.Set("Authorization", "Bearer "+req.key)
				// Changing the host must not escape the selected model's bucket.
				if i%2 == 1 {
					r.Header.Set("X-Forwarded-Host", otherModel+"."+*domain)
				}
				before := calls
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, r)
				if req.status == http.StatusTooManyRequests {
					assertVideoRouterError(t, rec, req.status)
					if calls != before {
						t.Fatal("rate-limited request reached upstream")
					}
					if got := rec.Header().Get("Retry-After"); got != "45" {
						t.Fatalf("Retry-After=%q, want 45", got)
					}
				} else if rec.Code != http.StatusOK || calls != before+1 || rec.Header().Get("Retry-After") != "" {
					t.Fatalf("request %d: status=%d calls=%d body=%s", i, rec.Code, calls, rec.Body.String())
				}
			}
			// The same key/model is admitted again after the shared window resets.
			now = now.Truncate(time.Minute).Add(time.Minute)
			body, _ := videoTestForm(t, videoTestModel)
			r := videoTestRequest(body, contentType)
			r.Header.Set("Authorization", "Bearer key-a-fixture")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, r)
			if rec.Code != http.StatusOK || calls != 5 {
				t.Fatalf("window reset: status=%d calls=%d", rec.Code, calls)
			}
		})
	}
}

func TestVideoRouterTrustedPriorityAdmission(t *testing.T) {
	for _, policy := range []string{"hard limit", "soft limit", "overload", "below limits"} {
		for _, tc := range []struct {
			name, response string
			status         int
			trusted        bool
			org            string
		}{
			{"configured negative", `{"priority":-1,"org_id":"org-fixture"}`, http.StatusOK, true, "org-fixture"},
			{"configured zero", `{"priority":0,"org_id":"org-fixture"}`, http.StatusOK, true, "org-fixture"},
			{"configured positive", `{"priority":1,"org_id":"org-fixture"}`, http.StatusOK, true, "org-fixture"},
			{"org without priority", `{"org_id":"org-fixture"}`, http.StatusOK, false, "org-fixture"},
			{"null priority", `{"priority":null}`, http.StatusOK, false, ""},
			{"failed lookup", `{"priority":-1,"org_id":"org-fixture"}`, http.StatusForbidden, false, ""},
			{"malformed context", `{"priority":"-1"}`, http.StatusOK, false, ""},
		} {
			t.Run(policy+"/"+tc.name, func(t *testing.T) {
				var lookups atomic.Int64
				controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					lookups.Add(1)
					var req routeContextRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.APIKey != "video-test-only-token" {
						t.Error("route context did not receive the caller's bearer token")
					}
					if r.Method != http.MethodPost || r.URL.Path != routeContextPath {
						t.Error("incorrect route-context lookup")
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.status)
					io.WriteString(w, tc.response)
				}))
				t.Cleanup(controlPlane.Close)
				body, _ := videoTestForm(t, videoTestModel)
				const contentType = `Multipart/Form-Data; charset=utf-8; boundary="video-test-boundary"`
				calls := 0
				em := manager.NewVideoRouterTestManager(map[string]http.Handler{
					videoTestModel: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls++
						got, err := io.ReadAll(r.Body)
						if err != nil || !bytes.Equal(got, body) {
							t.Error("configured priority must not inject or rewrite multipart bytes")
						}
						if r.Header.Get("Content-Type") != contentType || r.Header.Get("Authorization") != "Bearer video-test-only-token" {
							t.Error("configured priority changed request headers")
						}
						if got := manager.CallerOrgFromContext(r.Context()); got != tc.org {
							t.Errorf("caller org=%q, want %q", got, tc.org)
						}
						w.Header().Set("Content-Type", "video/mp4")
						w.Write([]byte{0, 0xff})
					}),
				}, ratelimit.WithNowFunc(func() time.Time {
					return time.Date(2026, 1, 1, 12, 0, 15, 500000000, time.UTC)
				}))
				model, _ := em.GetModel(videoTestModel)
				wantRetry := "45"
				switch policy {
				case "below limits":
					model.RateLimit = &config.RateLimitConfig{MaxRequestsPerMinute: 2, HardMaxRequestsPerMinute: 3}
				case "hard limit":
					model.RateLimit = &config.RateLimitConfig{HardMaxRequestsPerMinute: 1}
				case "soft limit":
					model.RateLimit = &config.RateLimitConfig{MaxRequestsPerMinute: 1}
				case "overload":
					for _, enclave := range model.Enclaves {
						enclave.SetVideoRouterTestOverloaded()
					}
					wantRetry = "60"
				}
				r := videoTestRequest(body, contentType)
				// Neither an untrusted header nor the org alone grants priority.
				r.Header.Set("Priority", "-999")
				r.Header.Set("X-Tinfoil-Org-Id", "attacker-org")
				rec := httptest.NewRecorder()
				newRouterHandler(em, newRouteContextClient(controlPlane.URL)).ServeHTTP(rec, r)
				if tc.trusted || policy == "below limits" {
					if rec.Code != http.StatusOK || calls != 1 || rec.Header().Get("Retry-After") != "" {
						t.Fatalf("trusted priority: status=%d calls=%d body=%s", rec.Code, calls, rec.Body.String())
					}
				} else {
					assertVideoRouterError(t, rec, http.StatusTooManyRequests)
					if calls != 0 || rec.Header().Get("Retry-After") != wantRetry {
						t.Fatalf("untrusted admission: calls=%d Retry-After=%q", calls, rec.Header().Get("Retry-After"))
					}
				}
				if lookups.Load() != 1 {
					t.Fatalf("route-context lookups=%d, want 1", lookups.Load())
				}
			})
		}
	}
}

func TestVideoRouterRejectsClientPriority(t *testing.T) {
	body, contentType := videoTestForm(t, videoTestModel)
	for _, disposition := range []string{
		`name="priority"`,
		`name="priority"; filename="priority.txt"`,
		`name="Priority"`,
		`name*=UTF-8''priority`,
	} {
		for _, beforeModel := range []bool{false, true} {
			for _, trusted := range []bool{false, true} {
				t.Run(disposition+"/before="+strconv.FormatBool(beforeModel)+"/trusted="+strconv.FormatBool(trusted), func(t *testing.T) {
					priorityPart := []byte("--video-test-boundary\r\nContent-Disposition: form-data; " + disposition + "\r\n\r\n-999\r\n")
					var attack []byte
					if beforeModel {
						attack = append(priorityPart, body...)
					} else {
						closing := []byte("--video-test-boundary--\r\n")
						attack = bytes.Replace(body, closing, append(priorityPart, closing...), 1)
					}
					calls := 0
					em := manager.NewVideoRouterTestManager(map[string]http.Handler{
						videoTestModel: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }),
					})
					var client *routeContextClient
					if trusted {
						priority := -1
						client = newRouteContextClient("https://control-plane.test.invalid")
						client.cache[routeContextCacheKey("video-test-only-token")] = cachedRouteContext{
							context: routeContext{Priority: &priority, OrgID: "org-fixture"},
							expires: time.Now().Add(time.Hour),
						}
					}
					rec := httptest.NewRecorder()
					newRouterHandler(em, client).ServeHTTP(rec, videoTestRequest(attack, contentType))
					assertVideoRouterError(t, rec, http.StatusBadRequest)
					if calls != 0 {
						t.Fatal("client priority reached upstream")
					}
				})
			}
		}
	}
}
