/*
Copyright The Ratify Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ratify-project/ratify/pkg/common/plugin/logger"
	spb "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// statementMockVerifier is a mock verifier for statement tests.
type statementMockVerifier struct {
	statement *spb.Statement
	err       error
}

func (m *statementMockVerifier) Verify(_ string) (*verify.VerificationResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &verify.VerificationResult{
		Statement: m.statement,
	}, nil
}

func newBundleReaderFromLines(lines []string, v Verifier) *BundleReader {
	var buf bytes.Buffer
	for _, line := range lines {
		buf.WriteString(line + "\n")
	}
	return NewBundleReader(bufio.NewReader(&buf), v)
}

func TestReadStatement_ValidLine(t *testing.T) {
	stmt := &spb.Statement{
		Type:          spb.StatementTypeUri,
		PredicateType: "https://slsa.dev/verification_summary/v1",
	}
	v := &statementMockVerifier{statement: stmt}
	br := newBundleReaderFromLines([]string{"valid-line"}, v)

	result, err := br.ReadStatement("https://slsa.dev/verification_summary/v1")
	if err != nil {
		t.Fatalf("ReadStatement() unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("ReadStatement() got nil, want statement")
	}
	if result.GetPredicateType() != "https://slsa.dev/verification_summary/v1" {
		t.Fatalf("ReadStatement() predicate type = %q, want %q", result.GetPredicateType(), "https://slsa.dev/verification_summary/v1")
	}
}

func TestReadStatement_PredicateTypeMismatch(t *testing.T) {
	stmt := &spb.Statement{
		Type:          spb.StatementTypeUri,
		PredicateType: "https://slsa.dev/provenance/v1",
	}
	v := &statementMockVerifier{statement: stmt}
	br := newBundleReaderFromLines([]string{"valid-line"}, v)

	result, err := br.ReadStatement("https://slsa.dev/verification_summary/v1")
	if err != nil {
		t.Fatalf("ReadStatement() unexpected error: %v", err)
	}
	if result != nil {
		t.Fatalf("ReadStatement() expected nil for mismatched predicate type, got %v", result)
	}
}

func TestReadStatement_EmptyPredicateFilter(t *testing.T) {
	stmt := &spb.Statement{
		Type:          spb.StatementTypeUri,
		PredicateType: "https://slsa.dev/provenance/v1",
	}
	v := &statementMockVerifier{statement: stmt}
	br := newBundleReaderFromLines([]string{"valid-line"}, v)

	result, err := br.ReadStatement("")
	if err != nil {
		t.Fatalf("ReadStatement() unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("ReadStatement() got nil, want statement (empty filter should match any)")
	}
}

func TestReadStatement_EmptyInput(t *testing.T) {
	v := &statementMockVerifier{err: errors.New("should not be called")}
	br := newBundleReaderFromLines([]string{}, v)

	result, err := br.ReadStatement("")
	if err != nil {
		t.Fatalf("ReadStatement() unexpected error: %v", err)
	}
	if result != nil {
		t.Fatalf("ReadStatement() expected nil for empty input, got %v", result)
	}
}

func TestReadStatement_AllEmptyLines(t *testing.T) {
	v := &statementMockVerifier{err: errors.New("should not be called")}
	// newBundleReaderFromLines adds \n after each line, so empty string becomes just \n
	br := newBundleReaderFromLines([]string{"", "", ""}, v)

	result, err := br.ReadStatement("")
	if err != nil {
		t.Fatalf("ReadStatement() unexpected error: %v", err)
	}
	if result != nil {
		t.Fatalf("ReadStatement() expected nil for all empty lines, got %v", result)
	}
}

func TestReadStatement_VerificationFailureContinues(t *testing.T) {
	callCount := 0
	stmt := &spb.Statement{
		Type:          spb.StatementTypeUri,
		PredicateType: "https://slsa.dev/verification_summary/v1",
	}
	// First call fails, second succeeds
	v := &countingMockVerifier{
		callCount: &callCount,
		results: []mockResult{
			{err: errors.New("verification failed")},
			{statement: stmt},
		},
	}
	br := newBundleReaderFromLines([]string{"bad-line", "good-line"}, v)

	result, err := br.ReadStatement("https://slsa.dev/verification_summary/v1")
	if err != nil {
		t.Fatalf("ReadStatement() unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("ReadStatement() got nil, want statement from second line")
	}
}

func TestReadStatement_NilStatementSkipped(t *testing.T) {
	callCount := 0
	stmt := &spb.Statement{
		Type:          spb.StatementTypeUri,
		PredicateType: "https://slsa.dev/verification_summary/v1",
	}
	// First call returns nil statement, second returns valid
	v := &countingMockVerifier{
		callCount: &callCount,
		results: []mockResult{
			{statement: nil},
			{statement: stmt},
		},
	}
	br := newBundleReaderFromLines([]string{"nil-stmt-line", "good-line"}, v)

	result, err := br.ReadStatement("https://slsa.dev/verification_summary/v1")
	if err != nil {
		t.Fatalf("ReadStatement() unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("ReadStatement() got nil, want statement from second line")
	}
}

func TestReadStatement_LongLineSkipped(t *testing.T) {
	stmt := &spb.Statement{
		Type:          spb.StatementTypeUri,
		PredicateType: "https://slsa.dev/verification_summary/v1",
	}
	callCount := 0
	v := &countingMockVerifier{
		callCount: &callCount,
		results: []mockResult{
			{statement: stmt}, // this should be the one returned (long line skipped)
		},
	}

	longLine := strings.Repeat("x", limitLineSize+1)
	br := newBundleReaderFromLines([]string{longLine, "good-line"}, v)

	result, err := br.ReadStatement("https://slsa.dev/verification_summary/v1")
	if err != nil {
		t.Fatalf("ReadStatement() unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("ReadStatement() got nil, want statement (long line should be skipped)")
	}
}

func TestConvertLineToStatement_VerifierSuccess(t *testing.T) {
	stmt := &spb.Statement{
		Type:          spb.StatementTypeUri,
		PredicateType: "https://slsa.dev/verification_summary/v1",
	}
	v := &statementMockVerifier{statement: stmt}
	br := NewBundleReader(nil, v)

	testLogger := logger.NewLogger()
	result, err := br.convertLineToStatement("test-line", testLogger)
	if err != nil {
		t.Fatalf("convertLineToStatement() unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("convertLineToStatement() got nil, want statement")
	}
}

func TestConvertLineToStatement_VerifierFailure(t *testing.T) {
	v := &statementMockVerifier{err: errors.New("generic error")}
	br := NewBundleReader(nil, v)

	testLogger := logger.NewLogger()
	result, err := br.convertLineToStatement("test-line", testLogger)
	if err == nil {
		t.Fatal("convertLineToStatement() expected error, got nil")
	}
	if result != nil {
		t.Fatalf("convertLineToStatement() expected nil result, got %v", result)
	}
	if !strings.Contains(err.Error(), "could not convert line to statement") {
		t.Fatalf("convertLineToStatement() error = %v, want containing 'could not convert line to statement'", err)
	}
}

func TestConvertLineToStatement_CertIdentityFallback(t *testing.T) {
	// Simulate "no matching CertificateIdentity" error containing OldExpectedSan
	identityErr := fmt.Errorf("no matching CertificateIdentity found: %s", OldExpectedSan)
	v := &statementMockVerifier{err: identityErr}
	br := NewBundleReader(nil, v)

	// The fallback creates a real BndVerifier which will fail on "test-line",
	// so we expect an error wrapping the original identity error.
	testLogger := logger.NewLogger()
	result, err := br.convertLineToStatement("test-line", testLogger)
	if result != nil {
		t.Fatalf("convertLineToStatement() expected nil result for fallback failure, got %v", result)
	}
	if err == nil {
		t.Fatal("convertLineToStatement() expected error from fallback path, got nil")
	}
	if !strings.Contains(err.Error(), "could not convert line to statement") {
		t.Fatalf("convertLineToStatement() error = %v, want containing 'could not convert line to statement'", err)
	}
}

// countingMockVerifier returns different results for successive calls.
type countingMockVerifier struct {
	callCount *int
	results   []mockResult
}

type mockResult struct {
	statement *spb.Statement
	err       error
}

func (m *countingMockVerifier) Verify(_ string) (*verify.VerificationResult, error) {
	idx := *m.callCount
	*m.callCount++
	if idx >= len(m.results) {
		return nil, errors.New("unexpected call")
	}
	r := m.results[idx]
	if r.err != nil {
		return nil, r.err
	}
	return &verify.VerificationResult{
		Statement: r.statement,
	}, nil
}
