package cache

import (
	"fmt"
	"testing"
)

func TestMatchFunctionAWS(t *testing.T) {
	// Test cases for AWS ARN wildcard matching
	testCases := []struct {
		pattern     string
		value       string
		expected    bool
		description string
	}{
		{"arn:aws:s3:::bucket-*", "arn:aws:s3:::bucket-123", true, "Should match: wildcard in bucket name"},
		{"arn:aws:s3:::bucket-*", "arn:aws:s3:::bucket-123/file", false, "Should NOT match: wildcard doesn't cross / boundary"},
		{"arn:aws:s3:::bucket-*/file", "arn:aws:s3:::bucket-123/file", true, "Should match: wildcard before /"},
		{"arn:aws:s3:::bucket-*/file", "arn:aws:s3:::bucket-123/other", false, "Should NOT match: different file name"},
		{"s3:Get*", "s3:GetObject", true, "Should match: action wildcard"},
		{"s3:Get*", "s3:PutObject", false, "Should NOT match: different action"},
		{"*", "anything", true, "Should match: full wildcard"},
		{"arn:aws:s3:::bucket-*/file*", "arn:aws:s3:::bucket-123/file.txt", true, "Should match: multiple wildcards"},
		{"arn:aws:s3:::bucket-*/file*", "arn:aws:s3:::bucket-123/dir/file.txt", false, "Should NOT match: wildcard doesn't cross /"},
	}

	for _, tc := range testCases {
		result := match(tc.pattern, tc.value)
		if result != tc.expected {
			t.Errorf("FAIL: match(%q, %q) = %v (expected %v) - %s",
				tc.pattern, tc.value, result, tc.expected, tc.description)
		} else {
			fmt.Printf("PASS: match(%q, %q) = %v - %s\n",
				tc.pattern, tc.value, result, tc.description)
		}
	}
}
