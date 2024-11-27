package secrets

import (
	"testing"

	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/stretchr/testify/assert"
)

func TestSecret(t *testing.T) {

	s := &Handler{key: "asdfasdfasdf"}

	encryptedStr, err := s.Encrypt([]byte("mycoolstring"))
	assert.NoError(t, err)

	decryptedStr, err := s.decrypt(string(encryptedStr))
	assert.NoError(t, err)
	assert.Equal(t, "mycoolstring", decryptedStr)
}
func TestSecretWrongKey(t *testing.T) {

	s := &Handler{key: "asdfasdfasdf"}

	encryptedStr, err := s.Encrypt([]byte("mycoolstring"))
	assert.NoError(t, err)

	s.key = "otherkey"
	decryptedStr, err := s.decrypt(string(encryptedStr))
	assert.Error(t, err)
	assert.Equal(t, "", decryptedStr)
}
func TestDecryptFilesContent(t *testing.T) {

	s := &Handler{key: "asdfasdfasdf"}

	files := types.Files{
		{
			Content: "my cool test file content",
		},
		{
			Content: `my cool test file content with {{secret "74bdee2ddc4cd92918e52932433a97aad3d57640384a476d32a3055edcb96c55210e55f0682d4ec2"}}`,
		},
	}

	err := s.DecryptFilesContent(files)
	assert.NoError(t, err)

	assert.Equal(t, "my cool test file content", files[0].Content)
	assert.Equal(t, "my cool test file content with mycoolstring", files[1].Content)
}
