package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"reflect"
	"strings"
	"testing"
)

// Synthetic names deliberately do not encode any deployed model or capability.
const videoTestModel = "configured-video-fixture"

func videoTestForm(t *testing.T, models ...string) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.SetBoundary("video-test-boundary"); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("prompt", "a test scene\r\nwith a second line"); err != nil {
		t.Fatal(err)
	}
	for _, model := range models {
		if err := writer.WriteField("model", model); err != nil {
			t.Fatal(err)
		}
	}
	part, err := writer.CreateFormFile("image", "frame.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte{0, 1, 2, '\r', '\n', 0xff, 0xfe}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes(), writer.FormDataContentType()
}

func videoTestRequest(body []byte, contentType string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/videos/sync", bytes.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	r.Header.Set("Authorization", "Bearer video-test-only-token")
	return r
}

func TestVideoModelValidPreservesRequest(t *testing.T) {
	body, _ := videoTestForm(t, videoTestModel)
	// Keep a noncanonical but valid header spelling/parameter order and a
	// quoted boundary, so re-encoding the form or header cannot pass unnoticed.
	contentType := `Multipart/Form-Data; charset=utf-8; boundary="video-test-boundary"`
	for _, forwardedHost := range []string{"", "other.router.example", "other.router.example:443", ".router.example"} {
		t.Run(forwardedHost, func(t *testing.T) {
			r := videoTestRequest(body, contentType)
			r.Host = "other.router.example"
			r.Header.Set("X-Forwarded-Host", forwardedHost)
			r.Header.Set("Forwarded", "host=other.router.example")
			wantHeaders := r.Header.Clone()
			wantLength := r.ContentLength
			if !limitRequestBody(httptest.NewRecorder(), r) {
				t.Fatal("valid request rejected by size limit")
			}
			model, err := parseRequestModel(r, "router.example")
			if err != nil || model != videoTestModel {
				t.Fatalf("model = %q, err = %v", model, err)
			}
			got, err := io.ReadAll(r.Body)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatalf("request body changed or unreadable: %v", err)
			}
			if !reflect.DeepEqual(r.Header, wantHeaders) || r.ContentLength != wantLength {
				t.Fatalf("request metadata changed: headers=%v length=%d", r.Header, r.ContentLength)
			}
			if r.MultipartForm != nil {
				t.Fatal("parser must not use ParseMultipartForm or spool files")
			}
		})
	}
}

func TestVideoModelValidation(t *testing.T) {
	valid, contentType := videoTestForm(t, videoTestModel)
	missing, _ := videoTestForm(t)
	empty, _ := videoTestForm(t, "")
	blank, _ := videoTestForm(t, " \t\r\n")
	leading, _ := videoTestForm(t, " "+videoTestModel)
	trailing, _ := videoTestForm(t, videoTestModel+"\u00a0")
	duplicate, _ := videoTestForm(t, videoTestModel, videoTestModel)
	conflicting, _ := videoTestForm(t, videoTestModel, "other-fixture")
	modelHeader := `Content-Disposition: form-data; name="model"`
	cases := []struct {
		name string
		body []byte
		want string
	}{
		{"missing", missing, "missing required parameter"},
		{"empty", empty, "model must be nonempty"},
		{"blank", blank, "model must be nonempty"},
		{"leading whitespace", leading, "model must be nonempty"},
		{"trailing unicode whitespace", trailing, "model must be nonempty"},
		{"duplicate", duplicate, "exactly one plain model"},
		{"conflicting duplicate", conflicting, "exactly one plain model"},
		{"file model", bytes.Replace(valid, []byte(modelHeader), []byte(modelHeader+`; filename="model.txt"`), 1), "exactly one plain model"},
		{"empty filename", bytes.Replace(valid, []byte(modelHeader), []byte(modelHeader+`; filename=""`), 1), "exactly one plain model"},
		{"extended filename", bytes.Replace(valid, []byte(modelHeader), []byte(modelHeader+`; filename*=utf-8''model.txt`), 1), "exactly one plain model"},
		{"duplicate file model", bytes.Replace(valid, []byte(`name="image"`), []byte(`name="model"`), 1), "exactly one plain model"},
		{"encoded selector", bytes.Replace(valid, []byte(modelHeader), []byte(modelHeader+"\r\nContent-Transfer-Encoding: quoted-printable"), 1), "exactly one plain model"},
		{"base64 selector", bytes.Replace(valid, []byte(modelHeader), []byte(modelHeader+"\r\nContent-Transfer-Encoding: base64"), 1), "exactly one plain model"},
		{"duplicate disposition", bytes.Replace(valid, []byte(modelHeader), []byte(modelHeader+"\r\n"+modelHeader), 1), "invalid multipart Content-Disposition"},
		{"invalid disposition after model", bytes.Replace(valid, []byte(`form-data; name="image"`), []byte(`attachment; name="image"`), 1), "invalid multipart Content-Disposition"},
		{"missing part name", bytes.Replace(valid, []byte(`name="image"`), []byte(`name=""`), 1), "invalid multipart Content-Disposition"},
		{"malformed header after model", bytes.Replace(valid, []byte(`Content-Disposition: form-data; name="image"`), []byte("not a valid header"), 1), "malformed multipart form"},
		{"missing closing boundary after model", valid[:len(valid)-len("--video-test-boundary--\r\n")], "malformed multipart form field"},
		{"truncated model", []byte("--video-test-boundary\r\n" + modelHeader + "\r\n\r\n" + videoTestModel), "malformed multipart model field"},
		{"not multipart", []byte("not a form"), "malformed multipart form"},
		{"empty body", nil, "malformed multipart form"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := videoTestRequest(tc.body, contentType)
			model, body, err := extractVideoModel(r)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
			if model != "" || body != nil {
				t.Fatalf("invalid form returned forwardable data: model=%q body bytes=%d", model, len(body))
			}
		})
	}
}

func TestVideoModelAfterFile(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Disposition":       {`form-data; name="image"; filename="frame.bin"`},
		"Content-Transfer-Encoding": {"binary"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte{0, 0xff, '\r', '\n'}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("model", videoTestModel); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	model, raw, err := extractVideoModel(videoTestRequest(body.Bytes(), writer.FormDataContentType()))
	if err != nil || model != videoTestModel || !bytes.Equal(raw, body.Bytes()) {
		t.Fatalf("model after file: model=%q err=%v raw preserved=%v", model, err, bytes.Equal(raw, body.Bytes()))
	}
}

func TestVideoModelFieldLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		model string
		valid bool
	}{
		{"256 bytes", strings.Repeat("m", 256), true},
		{"257 bytes", strings.Repeat("m", 257), false},
		{"256 UTF-8 bytes", strings.Repeat("é", 128), true},
		{"257 UTF-8 bytes", strings.Repeat("é", 128) + "m", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, contentType := videoTestForm(t, tc.model)
			model, raw, err := extractVideoModel(videoTestRequest(body, contentType))
			if tc.valid {
				if err != nil || model != tc.model || !bytes.Equal(raw, body) {
					t.Fatalf("model limit rejected or changed valid form: model=%q err=%v", model, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "model field exceeds 256 bytes") || model != "" || raw != nil {
				t.Fatalf("oversized selector: model=%q raw bytes=%d err=%v", model, len(raw), err)
			}
		})
	}
}

func videoTestParts(t *testing.T, count, modelIndex int) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for i := 0; i < count; i++ {
		if i == modelIndex {
			if err := writer.WriteField("model", videoTestModel); err != nil {
				t.Fatal(err)
			}
		} else if i%2 == 0 {
			// Repeated field names and empty parts must still count.
			if err := writer.WriteField("prompt", ""); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := writer.CreateFormFile("image", "frame.bin"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes(), writer.FormDataContentType()
}

func TestVideoMultipartPartLimit(t *testing.T) {
	for _, count := range []int{128, 129} {
		for _, modelIndex := range []int{0, count - 1} {
			t.Run(fmt.Sprintf("parts=%d/modelIndex=%d", count, modelIndex), func(t *testing.T) {
				body, contentType := videoTestParts(t, count, modelIndex)
				model, raw, err := extractVideoModel(videoTestRequest(body, contentType))
				if count == 128 {
					if err != nil || model != videoTestModel || !bytes.Equal(raw, body) {
						t.Fatalf("part limit rejected or changed valid form: model=%q err=%v", model, err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "video form exceeds 128 parts") || model != "" || raw != nil {
					t.Fatalf("too many parts: model=%q raw bytes=%d err=%v", model, len(raw), err)
				}
			})
		}
	}
}

func TestVideoMediaType(t *testing.T) {
	body, validType := videoTestForm(t, videoTestModel)
	for _, tc := range []struct {
		name        string
		types       []string
		unsupported bool
	}{
		{"missing", nil, true},
		{"json", []string{"application/json"}, true},
		{"urlencoded", []string{"application/x-www-form-urlencoded"}, true},
		{"mixed", []string{"multipart/mixed; boundary=video-test-boundary"}, true},
		{"missing boundary", []string{"multipart/form-data"}, false},
		{"empty boundary", []string{`multipart/form-data; boundary=""`}, false},
		{"invalid boundary parameter", []string{`multipart/form-data; boundary="unterminated`}, false},
		{"wrong boundary", []string{"multipart/form-data; boundary=wrong"}, false},
		{"duplicate header", []string{validType, validType}, false},
		{"conflicting headers", []string{validType, "application/json"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := videoTestRequest(body, "")
			for _, value := range tc.types {
				r.Header.Add("Content-Type", value)
			}
			_, err := parseRequestModel(r, "router.example")
			if err == nil || errors.Is(err, errVideoMediaType) != tc.unsupported {
				t.Fatalf("err = %v, want unsupported=%v", err, tc.unsupported)
			}
		})
	}
}

func TestVideoWrongMethod(t *testing.T) {
	body, contentType := videoTestForm(t, videoTestModel)
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			r := videoTestRequest(body, contentType)
			r.Method = method
			r.Header.Set("X-Forwarded-Host", "other.router.example")
			_, err := parseRequestModel(r, "router.example")
			if !errors.Is(err, errVideoMethod) {
				t.Fatalf("err = %v, want method error", err)
			}
			remaining, err := io.ReadAll(r.Body)
			if err != nil || !bytes.Equal(remaining, body) {
				t.Fatal("wrong-method request body was consumed")
			}
		})
	}
}

func TestVideoParserLeavesOtherRoutesAlone(t *testing.T) {
	body := []byte(`{"model":"body-fixture","messages":[]}`)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses", "/v1/videos/sync/"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Forwarded-Host", "host-fixture.router.example")
			model, err := parseRequestModel(r, "router.example")
			if err != nil || model != "host-fixture" {
				t.Fatalf("model=%q err=%v", model, err)
			}
			got, err := io.ReadAll(r.Body)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatal("non-video body was changed or consumed")
			}
		})
	}
}

func TestVideoModelBodyLimit(t *testing.T) {
	body, contentType := videoTestForm(t, videoTestModel)
	for _, limit := range []int64{int64(len(body)), int64(len(body) - 1)} {
		r := videoTestRequest(body, contentType)
		r.ContentLength = -1 // The reader limit, not Content-Length, must enforce this.
		r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, limit)
		model, err := parseRequestModel(r, "router.example")
		if limit == int64(len(body)) {
			if err != nil || model != videoTestModel {
				t.Fatalf("exact limit rejected: model=%q err=%v", model, err)
			}
		} else {
			var tooLarge *http.MaxBytesError
			if !errors.As(err, &tooLarge) || tooLarge.Limit != limit {
				t.Fatalf("size error not preserved: %v", err)
			}
		}
	}
}
