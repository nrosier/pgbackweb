package storage

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
)

// The AWS SDK's default of "WhenSupported" always attaches a request
// checksum to body-bearing calls like PutObject, sent as an aws-chunked
// trailer that some S3-compatible providers (e.g. Google Cloud Storage)
// fail to validate, causing every upload to fail with a 403
// SignatureDoesNotMatch even though checksum-free calls like HeadBucket
// succeed. This pins the client down to "WhenRequired" so it never
// regresses back to that default.
// See: https://github.com/aws/aws-sdk-go-v2/issues/2673
func TestCreateS3ClientDisablesDefaultChecksums(t *testing.T) {
	s3Client, err := createS3Client("access-key", "secret-key", "us-east-1", "http://localhost:9000")
	assert.NoError(t, err)

	opts := s3Client.Options()
	assert.Equal(t, aws.RequestChecksumCalculationWhenRequired, opts.RequestChecksumCalculation)
	assert.Equal(t, aws.ResponseChecksumValidationWhenRequired, opts.ResponseChecksumValidation)
}
