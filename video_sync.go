// Copyright 2026 Aptos Labs. Added to tinfoilsh/confidential-model-router on 2026-09-11.
// Licensed under the GNU Affero General Public License v3, like the rest of this program.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
)

const (
	maxVideoMultipartParts = 128
	maxVideoModelBytes     = 256
)

var (
	errVideoMediaType = errors.New("video sync requires multipart/form-data")
	errVideoMethod    = errors.New("video sync requires POST")
)

// parseRequestModel selects video sync models from the form, never from a
// forwarded host. Other routes retain their existing subdomain/body handling.
// The caller must apply limitRequestBody before calling this function.
func parseRequestModel(r *http.Request, domain string) (string, error) {
	if r.URL.Path != "/v1/videos/sync" {
		return parseModelFromSubdomain(r, domain)
	}
	if r.Method != http.MethodPost {
		return "", errVideoMethod
	}

	model, body, err := extractVideoModel(r)
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return model, nil
}

// extractVideoModel validates the entire form, including parts after the model,
// without re-encoding it or spooling uploads to disk. The buffered bytes remain
// subject to the router's existing request body limit.
func extractVideoModel(r *http.Request) (string, []byte, error) {
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) == 0 {
		return "", nil, errVideoMediaType
	}
	if len(contentTypes) != 1 {
		return "", nil, errors.New("expected one Content-Type header")
	}
	mediaType, params, err := mime.ParseMediaType(contentTypes[0])
	if err != nil {
		return "", nil, errors.New("invalid Content-Type header")
	}
	if mediaType != "multipart/form-data" {
		return "", nil, errVideoMediaType
	}
	boundary := params["boundary"]
	if boundary == "" {
		return "", nil, errors.New("missing multipart boundary")
	}

	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", nil, fmt.Errorf("read video form: %w", err)
	}

	var model string
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	for parts := 0; ; parts++ {
		// NextRawPart avoids silently decoding a quoted-printable selector
		// differently from a backend that reads the original form bytes.
		part, err := reader.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, errors.New("malformed multipart form")
		}
		if parts >= maxVideoMultipartParts {
			return "", nil, fmt.Errorf("video form exceeds %d parts", maxVideoMultipartParts)
		}
		disposition, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if err != nil || len(part.Header.Values("Content-Disposition")) != 1 ||
			disposition != "form-data" || params["name"] == "" {
			return "", nil, errors.New("invalid multipart Content-Disposition")
		}
		// JSON requests strip client priority before dispatch. Video must
		// preserve exact bytes, so reject priority parts (including files)
		// instead of forwarding untrusted queue controls or rewriting them.
		if strings.EqualFold(params["name"], "priority") {
			return "", nil, errors.New("video priority is controlled by the control plane, not multipart fields")
		}
		if params["name"] == "model" {
			if _, file := params["filename"]; file || model != "" ||
				len(part.Header.Values("Content-Transfer-Encoding")) != 0 {
				return "", nil, errors.New("expected exactly one plain model field, not a file")
			}
			// Read only one byte beyond the selector limit, not another body-sized copy.
			value, err := io.ReadAll(io.LimitReader(part, maxVideoModelBytes+1))
			if err != nil {
				return "", nil, errors.New("malformed multipart model field")
			}
			if len(value) > maxVideoModelBytes {
				return "", nil, fmt.Errorf("model field exceeds %d bytes", maxVideoModelBytes)
			}
			model = string(value)
			if model == "" || strings.TrimSpace(model) != model {
				return "", nil, errors.New("model must be nonempty with no surrounding whitespace")
			}
		} else if _, err := io.Copy(io.Discard, part); err != nil {
			return "", nil, errors.New("malformed multipart form field")
		}
	}
	if model == "" {
		return "", nil, errors.New("missing required parameter: 'model'")
	}
	return model, body, nil
}
