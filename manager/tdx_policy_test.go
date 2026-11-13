package manager

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/google/go-tdx-guest/proto/tdx"
)

var tdxPolicyNow = time.Date(2026, 11, 13, 16, 0, 0, 0, time.UTC)

func TestCapturedTdxPolicyAcceptsHostQuote(t *testing.T) {
	v2, v3 := tdxFixtures(t)
	if err := verifyCapturedTdxPolicy(v2, v3, tdxPolicyNow); err != nil {
		t.Fatal(err)
	}
}

func TestCapturedTdxPolicyRejects(t *testing.T) {
	v2, v3 := tdxFixtures(t)
	expired := time.Date(2026, 12, 14, 0, 0, 0, 0, time.UTC)
	if err := verifyCapturedTdxPolicy(v2, v3, expired); err == nil {
		t.Fatal("expired Intel collateral was accepted")
	}

	var tampered v3Attestation
	if err := json.Unmarshal(v3, &tampered); err != nil {
		t.Fatal(err)
	}
	response := &tampered.Collateral[0].Data.Responses[0]
	raw, err := base64.StdEncoding.DecodeString(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xff
	response.Body = base64.StdEncoding.EncodeToString(raw)
	tamperedJSON, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCapturedTdxPolicy(v2, tamperedJSON, tdxPolicyNow); err == nil || !strings.Contains(err.Error(), "collateral") {
		t.Fatalf("tampered collateral: %v", err)
	}

	var document v3Attestation
	if err := json.Unmarshal(v3, &document); err != nil {
		t.Fatal(err)
	}
	var kept []capturedResponse
	for _, response := range document.Collateral[0].Data.Responses {
		if !strings.Contains(response.URL, "/tcb?") {
			kept = append(kept, response)
		}
	}
	document.Collateral[0].Data.Responses = kept
	withoutTCB, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCapturedTdxPolicy(v2, withoutTCB, tdxPolicyNow); err == nil || !strings.Contains(err.Error(), "no response") {
		t.Fatalf("missing TCB info: %v", err)
	}
}

func TestTdxModulePolicyRejectsMutations(t *testing.T) {
	_, v3 := tdxFixtures(t)
	quote, _, err := quoteFromV3Document(v3)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*pb.QuoteV4)
	}{
		{"debug attributes", func(q *pb.QuoteV4) { q.TdQuoteBody.TdAttributes[0] = 0x01 }},
		{"xfam", func(q *pb.QuoteV4) { q.TdQuoteBody.Xfam[0] ^= 0xff }},
		{"owner", func(q *pb.QuoteV4) { q.TdQuoteBody.MrOwner[0] = 1 }},
		{"module measurement", func(q *pb.QuoteV4) { q.TdQuoteBody.MrSeam[0] ^= 0xff }},
		{"seam attributes", func(q *pb.QuoteV4) { q.TdQuoteBody.SeamAttributes[0] = 1 }},
		{"tcb svn", func(q *pb.QuoteV4) { q.TdQuoteBody.TeeTcbSvn[0] = 0x01 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := proto.Clone(quote).(*pb.QuoteV4)
			tc.mutate(mutated)
			if err := applyTdxModulePolicy(mutated); err == nil {
				t.Fatal("mutated quote was accepted")
			}
		})
	}
}

func TestTdxPlatformComparisonRejectsDifferentRegisters(t *testing.T) {
	_, v3 := tdxFixtures(t)
	quote, _, err := quoteFromV3Document(v3)
	if err != nil {
		t.Fatal(err)
	}
	other := proto.Clone(quote).(*pb.QuoteV4)
	other.TdQuoteBody.Rtmrs[2][0] ^= 0xff
	if err := sameTdxPlatform(quote, other); err == nil || !strings.Contains(err.Error(), "RTMR2") {
		t.Fatalf("err = %v", err)
	}
}

func TestCollateralMatchIgnoresExtraParameters(t *testing.T) {
	_, v3 := tdxFixtures(t)
	_, responses, err := quoteFromV3Document(v3)
	if err != nil {
		t.Fatal(err)
	}
	getter := capturedCollateral{responses: responses}
	body, _, err := getter.Get("https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000")
	if err != nil || len(body) == 0 {
		t.Fatalf("lowercase fmspc without update=standard: %v len=%d", err, len(body))
	}
	if _, _, err := getter.Get("https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=001122334455"); err == nil {
		t.Fatal("an uncaptured FMSPC was answered")
	}
}

func tdxFixtures(t *testing.T) (string, []byte) {
	t.Helper()
	v2Raw, err := os.ReadFile("testdata/tdx-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var v2 struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(v2Raw, &v2); err != nil {
		t.Fatal(err)
	}
	v3, err := os.ReadFile("testdata/tdx-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base64.StdEncoding.DecodeString(v2.Body); err != nil {
		t.Fatal(err)
	}
	return v2.Body, v3
}
