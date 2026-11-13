package manager

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
)

const (
	attestationV3Format  = "https://tinfoil.sh/predicate/attestation/v3"
	tdxQuoteV1Format     = "https://tinfoil.sh/format/tdx-quote/v1"
	intelPcsV1Format     = "https://tinfoil.sh/collateral/intel-pcs/v1"
	cpuCollateralSubject = "cpu"
	attestationNonceSize = 32
)

// Module measurements published by Intel for the TDX module versions the
// upstream verifier accepts. A host that boots a module outside this list is
// rejected until the list is updated.
var acceptedMrSeams = [][]byte{
	{0x47, 0x6a, 0x29, 0x97, 0xc6, 0x2b, 0xcc, 0xc7, 0x83, 0x70, 0x91, 0x3d, 0x0a, 0x80, 0xb9, 0x56, 0xe3, 0x72, 0x1b, 0x24, 0x27, 0x2b, 0xc6, 0x6c, 0x4d, 0x63, 0x07, 0xce, 0xd4, 0xbe, 0x28, 0x65, 0xc4, 0x0e, 0x26, 0xaf, 0xac, 0x75, 0xf1, 0x2d, 0xf3, 0x42, 0x5b, 0x03, 0xeb, 0x59, 0xea, 0x7c}, // 2.0.08
	{0x7b, 0xf0, 0x63, 0x28, 0x0e, 0x94, 0xfb, 0x05, 0x1f, 0x5d, 0xd7, 0xb1, 0xfc, 0x59, 0xce, 0x9a, 0xac, 0x42, 0xbb, 0x96, 0x1d, 0xf8, 0xd4, 0x4b, 0x70, 0x9c, 0x9b, 0x0f, 0xf8, 0x7a, 0x7b, 0x4d, 0xf6, 0x48, 0x65, 0x7b, 0xa6, 0xd1, 0x18, 0x95, 0x89, 0xfe, 0xab, 0x1d, 0x5a, 0x3c, 0x9a, 0x9d}, // 1.5.16
	{0x68, 0x5f, 0x89, 0x1e, 0xa5, 0xc2, 0x0e, 0x8f, 0xa2, 0x7b, 0x15, 0x1b, 0xf3, 0x4b, 0xf3, 0xb5, 0x0f, 0xba, 0xf7, 0x14, 0x3c, 0xc5, 0x36, 0x62, 0x72, 0x7c, 0xbd, 0xb1, 0x67, 0xc0, 0xad, 0x83, 0x85, 0xf1, 0xf6, 0xf3, 0x57, 0x15, 0x39, 0xa9, 0x1e, 0x10, 0x4a, 0x1c, 0x96, 0xd7, 0x5e, 0x04}, // 2.0.02
	{0x49, 0xb6, 0x6f, 0xaa, 0x45, 0x1d, 0x19, 0xeb, 0xbd, 0xbe, 0x89, 0x37, 0x1b, 0x8d, 0xaf, 0x2b, 0x65, 0xaa, 0x39, 0x84, 0xec, 0x90, 0x11, 0x03, 0x43, 0xe9, 0xe2, 0xee, 0xc1, 0x16, 0xaf, 0x08, 0x85, 0x0f, 0xa2, 0x0e, 0x3b, 0x1a, 0xa9, 0xa8, 0x74, 0xd7, 0x7a, 0x65, 0x38, 0x0e, 0xe7, 0xe6}, // 1.5.08
}

var intelQeVendorID = []byte{0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07}

// verifyCapturedTdxPolicy checks the key-bearing v2 quote and the v3 quote
// against the Intel collateral captured in the v3 document. The collateral is
// replayed locally: nothing in this function contacts Intel. now is the time
// at which the captured TCB info, quoting-enclave identity, and CRLs must
// still be valid.
func verifyCapturedTdxPolicy(v2Body string, v3Document []byte, now time.Time) error {
	v2Quote, err := quoteFromV2Body(v2Body)
	if err != nil {
		return fmt.Errorf("parsing v2 quote: %w", err)
	}
	v3Quote, responses, err := quoteFromV3Document(v3Document)
	if err != nil {
		return err
	}
	// Both quotes are checked against the captured collateral. The v2 quote is
	// the one whose report data binds the TLS key; the v3 quote carries no such
	// binding the router checks, so a v3 quote from another platform must not
	// vouch for the platform that serves traffic. A v2 quote whose PCK chain,
	// FMSPC, or TCB the collateral does not cover fails here.
	options := &verify.Options{
		GetCollateral:    true,
		CheckRevocations: true,
		Now:              now,
		Getter:           capturedCollateral{responses: responses},
	}
	if err := verify.TdxQuote(v2Quote, options); err != nil {
		return fmt.Errorf("verifying v2 quote against collateral: %w", err)
	}
	if err := verify.TdxQuote(v3Quote, options); err != nil {
		return fmt.Errorf("verifying TDX collateral: %w", err)
	}
	if err := applyTdxModulePolicy(v3Quote); err != nil {
		return err
	}
	if err := sameTdxPlatform(v2Quote, v3Quote); err != nil {
		return fmt.Errorf("v2 and v3 quotes describe different platforms: %w", err)
	}
	return nil
}

func applyTdxModulePolicy(quote *pb.QuoteV4) error {
	body := quote.GetTdQuoteBody()
	if body == nil {
		return errors.New("TDX quote has no TD body")
	}
	options := &validate.Options{
		HeaderOptions: validate.HeaderOptions{QeVendorID: intelQeVendorID},
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{
			// Minimum TEE TCB SVN 3.1.2.
			MinimumTeeTcbSvn: []byte{0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			TdAttributes:     []byte{0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00},
			Xfam:             []byte{0xe7, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00},
			MrConfigID:       make([]byte, 48),
			MrOwner:          make([]byte, 48),
			MrOwnerConfig:    make([]byte, 48),
		},
	}
	if err := validate.TdxQuote(quote, options); err != nil {
		return fmt.Errorf("TDX quote policy: %w", err)
	}
	for _, allowed := range acceptedMrSeams {
		if bytes.Equal(body.GetMrSeam(), allowed) {
			if seam := body.GetSeamAttributes(); len(seam) != 8 || !bytes.Equal(seam, make([]byte, 8)) {
				return errors.New("TDX SEAM attributes are not zero")
			}
			return nil
		}
	}
	return fmt.Errorf("TDX module measurement %x is not accepted", body.GetMrSeam())
}

func sameTdxPlatform(v2Quote, v3Quote *pb.QuoteV4) error {
	left, right := v2Quote.GetTdQuoteBody(), v3Quote.GetTdQuoteBody()
	if left == nil || right == nil {
		return errors.New("quote has no TD body")
	}
	pairs := []struct {
		name   string
		v2, v3 []byte
	}{
		{"MRSEAM", left.GetMrSeam(), right.GetMrSeam()},
		{"SEAM attributes", left.GetSeamAttributes(), right.GetSeamAttributes()},
		{"TEE TCB SVN", left.GetTeeTcbSvn(), right.GetTeeTcbSvn()},
		{"TD attributes", left.GetTdAttributes(), right.GetTdAttributes()},
		{"XFAM", left.GetXfam(), right.GetXfam()},
		{"MRTD", left.GetMrTd(), right.GetMrTd()},
		{"MRCONFIGID", left.GetMrConfigId(), right.GetMrConfigId()},
		{"MROWNER", left.GetMrOwner(), right.GetMrOwner()},
		{"MROWNERCONFIG", left.GetMrOwnerConfig(), right.GetMrOwnerConfig()},
	}
	for _, pair := range pairs {
		if !bytes.Equal(pair.v2, pair.v3) {
			return fmt.Errorf("%s differs", pair.name)
		}
	}
	if len(left.GetRtmrs()) != len(right.GetRtmrs()) {
		return fmt.Errorf("RTMR count differs")
	}
	for i := range left.GetRtmrs() {
		if !bytes.Equal(left.GetRtmrs()[i], right.GetRtmrs()[i]) {
			return fmt.Errorf("RTMR%d differs", i)
		}
	}
	return nil
}

func quoteFromV2Body(body string) (*pb.QuoteV4, error) {
	compressed, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, err
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, maxAttestationDocBytes))
	if err != nil {
		return nil, err
	}
	return quoteV4(raw)
}

type v3Attestation struct {
	Format      string `json:"format"`
	CPUEvidence struct {
		Format       string `json:"format"`
		ReportBase64 string `json:"report_base64"`
	} `json:"cpu_evidence"`
	Collateral []struct {
		Format   string   `json:"format"`
		Subjects []string `json:"subjects"`
		Data     struct {
			Responses []capturedResponse `json:"responses"`
		} `json:"data"`
	} `json:"collateral"`
}

type capturedResponse struct {
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body_base64"`
}

func quoteFromV3Document(raw []byte) (*pb.QuoteV4, []capturedResponse, error) {
	var document v3Attestation
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, nil, fmt.Errorf("parsing v3 attestation: %w", err)
	}
	if document.Format != attestationV3Format {
		return nil, nil, fmt.Errorf("v3 attestation has format %s", document.Format)
	}
	if document.CPUEvidence.Format != tdxQuoteV1Format {
		return nil, nil, fmt.Errorf("v3 evidence has format %s", document.CPUEvidence.Format)
	}
	quoteBytes, err := base64.StdEncoding.DecodeString(document.CPUEvidence.ReportBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding v3 quote: %w", err)
	}
	quote, err := quoteV4(quoteBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing v3 quote: %w", err)
	}
	var responses []capturedResponse
	for _, entry := range document.Collateral {
		if entry.Format != intelPcsV1Format {
			continue
		}
		if len(entry.Subjects) != 1 || entry.Subjects[0] != cpuCollateralSubject {
			return nil, nil, errors.New("intel-pcs collateral is not for the cpu")
		}
		responses = append(responses, entry.Data.Responses...)
	}
	if len(responses) == 0 {
		return nil, nil, errors.New("v3 attestation carries no intel-pcs collateral")
	}
	return quote, responses, nil
}

func quoteV4(raw []byte) (*pb.QuoteV4, error) {
	parsed, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, err
	}
	quote, ok := parsed.(*pb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("quote type %T", parsed)
	}
	return quote, nil
}

// capturedCollateral answers go-tdx-guest's Intel PCS requests from the
// responses the ATC stored in the attestation document. Captured URLs may
// carry extra parameters, such as update=standard, that the library does not
// send. A request the document cannot answer fails; it is never fetched.
type capturedCollateral struct {
	responses []capturedResponse
}

func (c capturedCollateral) Get(rawURL string) (map[string][]string, []byte, error) {
	requested, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	for _, response := range c.responses {
		captured, err := url.Parse(response.URL)
		if err != nil || !collateralURLMatches(requested, captured) {
			continue
		}
		body, err := base64.StdEncoding.DecodeString(response.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding captured response for %s: %w", rawURL, err)
		}
		return response.Headers, body, nil
	}
	return nil, nil, fmt.Errorf("attestation collateral has no response for %s", rawURL)
}

func collateralURLMatches(requested, captured *url.URL) bool {
	if requested.Scheme != "https" || !strings.EqualFold(requested.Hostname(), captured.Hostname()) {
		return false
	}
	if requested.EscapedPath() != captured.EscapedPath() {
		return false
	}
	capturedQuery := captured.Query()
	for key, values := range requested.Query() {
		have := capturedQuery[key]
		if len(have) != len(values) {
			return false
		}
		for i := range values {
			if !strings.EqualFold(values[i], have[i]) {
				return false
			}
		}
	}
	return true
}

func fetchAttestationV3(ctx context.Context, host string) ([]byte, error) {
	nonce := make([]byte, attestationNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	target := url.URL{Scheme: "https", Host: host, Path: "/.well-known/tinfoil-attestation"}
	query := target.Query()
	query.Set("nonce", hex.EncodeToString(nonce))
	target.RawQuery = query.Encode()
	body, err := getAttestation(ctx, target)
	if err != nil {
		return nil, err
	}
	return body, nil
}

var _ trust.HTTPSGetter = capturedCollateral{}
