package secrets

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"text/template"

	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
)

type Handler struct {
	key string
}

func NewHandler(key string) *Handler {
	return &Handler{key: key}
}

func (s *Handler) DecryptFilesContent(files types.Files) error {
	for _, file := range files {
		if file.Content != "" {
			tmpl, err := template.New("secret").Funcs(template.FuncMap{
				"secret": s.decrypt,
			}).Parse(file.Content)
			if err != nil {
				return err
			}

			var buf bytes.Buffer
			err = tmpl.Execute(&buf, nil)
			if err != nil {
				return err
			}

			file.Content = buf.String()
		}
	}
	return nil
}

func (s *Handler) Encrypt(plaintext []byte) ([]byte, error) {
	key := sha256.Sum256([]byte(s.key))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	dst := make([]byte, hex.EncodedLen(len(ciphertext)))
	hex.Encode(dst, ciphertext)
	return dst, nil
}

func (s *Handler) decrypt(encryptedStr string) (string, error) {
	ciphertext, err := hex.DecodeString(encryptedStr)
	if err != nil {
		return "", err
	}

	key := sha256.Sum256([]byte(s.key))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
