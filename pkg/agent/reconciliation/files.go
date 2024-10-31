package reconciliation

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/sirupsen/logrus"
)

func (mr *MachineReconciler) files(files types.Files) error {
	for _, file := range files {
		if file.URL != "" && file.Content != "" {
			logrus.Error(fmt.Errorf("file can only have Content or URL, not both"))
			continue
		}

		if file.URL != "" {
			changed, err := fetchFromURL(file)
			if err != nil {
				logrus.Errorf("files: %s failed to fetch from URL with error: %s", file.Path, err)
				continue
			}
			if changed {
				mr.unitNeedsTrigger(file.Systemd)
			}
			continue
		}

		if file.Content != "" {
			changed, err := writeContentIfNeeded(file)
			if err != nil {
				logrus.Errorf("files: %s failed write file content with error: %s", file.Path, err)
				continue
			}
			if changed {
				mr.unitNeedsTrigger(file.Systemd)
			}
			continue
		}
	}
	return nil
}

func writeContentIfNeeded(file *types.File) (bool, error) {
	mode, err := file.FileMode()
	if err != nil {
		return false, err
	}
	statedFile, err := os.Stat(file.Path)
	if errors.Is(err, os.ErrNotExist) { // New file we can write directly to desired location
		err = os.WriteFile(file.Path, []byte(file.Content), mode)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	equal := true
	if int64(len(file.Content)) != statedFile.Size() {
		equal, err = fileEqual(file.Content, file.Path)
		if err != nil {
			return false, err
		}
	}
	if equal {
		if mode != statedFile.Mode() { // check if content was same but we need to update mode
			err = os.Chmod(file.Path, mode)
			if err != nil {
				return false, err
			}
		}
		logrus.Debug(file.Path, " already equal")
		return false, nil
	}

	// existing file we make a tempfile in the same target directory and then atomic move.
	tempFile, err := os.CreateTemp(filepath.Dir(file.Path), "gmc")
	if err != nil {
		return false, err
	}
	defer tempFile.Close()
	err = tempFile.Chmod(mode)

	if err != nil {
		return false, err
	}

	_, err = io.Copy(tempFile, bytes.NewBufferString(file.Content))
	if err != nil {
		return false, err
	}

	tempFile.Close() // close it so we can rename it (move it)
	err = os.Rename(tempFile.Name(), file.Path)
	if err != nil {
		return false, err
	}
	return true, nil
}

func needsFetch(file *types.File) (bool, error) {
	f, err := os.Open(file.Path)
	if err != nil && os.IsNotExist(err) {
		return true, nil // file does not exist it needs fetching
	}
	if err != nil {
		return false, err
	}
	defer f.Close()

	equal, err := hashIsEqual(f, file.Checksum)
	if err != nil {
		return false, err
	}

	if !equal {
		return true, nil // checksum mismatch file needs fetching
	}
	return false, nil
}

func hashIsEqual(r io.Reader, checksum string) (bool, error) {
	var h hash.Hash
	switch len(checksum) {
	case 64:
		h = sha256.New()
	case 128:
		h = sha512.New()
	default:
		return false, fmt.Errorf("wrong checksum length expected 64(sha256) or 128(sha512)")
	}

	if _, err := io.Copy(h, r); err != nil {
		return false, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	return sum == checksum, nil
}

// fetchFromURL returns changed bool and an error.
func fetchFromURL(file *types.File) (bool, error) {
	missing, err := needsFetch(file)
	if err != nil {
		return false, err
	}

	// exit early if checksum already is correct.
	if !missing {
		return false, nil
	}

	mode, err := file.FileMode()
	if err != nil {
		return false, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, file.URL, nil)
	if err != nil {
		return false, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}

	defer resp.Body.Close()

	tempFile, err := os.CreateTemp(filepath.Dir(file.Path), "gmc")
	if err != nil {
		return false, err
	}
	defer tempFile.Close()

	tempFile.Chmod(mode)

	_, err = io.Copy(tempFile, resp.Body)
	if err != nil {
		return false, err
	}

	if file.ExtractFile != "" {
		tempFile.Seek(0, io.SeekStart)
		newTempFile, err := os.CreateTemp(filepath.Dir(file.Path), "gmc")
		if err != nil {
			return false, err
		}
		defer newTempFile.Close()
		newTempFile.Chmod(mode)

		err = extractTarGz(tempFile, newTempFile, file.ExtractFile)
		if err != nil {
			return false, err
		}

		newTempFile.Seek(0, io.SeekStart)
		equal, err := hashIsEqual(newTempFile, file.Checksum)
		if err != nil {
			return false, err
		}
		if !equal {
			return false, fmt.Errorf("checksum mismatch. expected file to be %s", file.Checksum)
		}
		return true, os.Rename(newTempFile.Name(), file.Path)
	}

	tempFile.Seek(0, io.SeekStart)
	equal, err := hashIsEqual(tempFile, file.Checksum)
	if err != nil {
		return false, err
	}
	if !equal {
		return false, fmt.Errorf("checksum mismatch. expected file to be %s", file.Checksum)
	}
	return true, os.Rename(tempFile.Name(), file.Path)
}

func extractTarGz(r io.Reader, w io.Writer, singleFile string) error {
	uncompressedStream, err := gzip.NewReader(r)
	if err != nil {
		return err
	}

	tarReader := tar.NewReader(uncompressedStream)

	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// if err := os.Mkdir(header.Name, 0755); err != nil {
			// 	log.Fatalf("ExtractTarGz: Mkdir() failed: %s", err.Error())
			// }
		case tar.TypeReg:
			if header.Name != singleFile {
				continue
			}
			if _, err := io.Copy(w, tarReader); err != nil {
				return err
			}
			return nil
		default:
			return fmt.Errorf("files extraction: uknown type: %d in %s",
				header.Typeflag,
				header.Name)
		}
	}
	return nil
}

const chunkSize = 4 * 1024

func fileEqual(content, file string) (same bool, err error) {
	// long way: compare contents
	f1, err := os.Open(file)
	if err != nil {
		return false, err
	}
	defer f1.Close()

	f2 := bytes.NewBufferString(content)

	b1 := make([]byte, chunkSize)
	b2 := make([]byte, chunkSize)
	for {
		n1, err1 := io.ReadFull(f1, b1)
		n2, err2 := io.ReadFull(f2, b2)

		// https://pkg.go.dev/io#Reader
		// > Callers should always process the n > 0 bytes returned
		// > before considering the error err. Doing so correctly
		// > handles I/O errors that happen after reading some bytes
		// > and also both of the allowed EOF behaviors.

		if !bytes.Equal(b1[:n1], b2[:n2]) {
			return false, nil
		}

		if (err1 == io.EOF && err2 == io.EOF) || (err1 == io.ErrUnexpectedEOF && err2 == io.ErrUnexpectedEOF) {
			return true, nil
		}

		// some other error, like a dropped network connection or a bad transfer
		if err1 != nil {
			return false, err1
		}
		if err2 != nil {
			return false, err2
		}
	}
}
