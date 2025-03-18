package e2e_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func getBody(t *testing.T, b io.ReadCloser) string {

	d, err := io.ReadAll(b)
	assert.NoError(t, err)
	return string(d)
}
