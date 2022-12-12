package reconciliation

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
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
			// TODO no return
			logrus.Error(fmt.Errorf("file can only have Content or URL, not both"))
			continue
		}

		if file.URL != "" {
			err := fetchFromURL(file)
			if err != nil {
				logrus.Error(err)
			}
			continue
		}

		if file.Content != "" {
			// TODO check if there is a diff first
			equal, err := fileEqual(file.Content, file.Path)
			if err != nil {
				logrus.Error(err)
				continue
			}
			if equal {
				logrus.Info(file.Path, " already equal")
				continue
			}

			mode, err := file.FileMode()
			if err != nil {
				logrus.Error(err)
				continue
			}

			// TODO writefile ONLY if it did not exist. If it exists we need to make atomic move?
			err = os.WriteFile(file.Path, []byte(file.Content), mode)
			if err != nil {
				logrus.Error(err)
			}
			continue
		}
		// TODO add each changed file to mrestartUnits if we have SystemdReference on the file.
	}
	return nil
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

	var h hash.Hash
	switch len(file.Checksum) {
	case 64:
		h = sha256.New()
	case 128:
		h = sha512.New()
	default:
		return false, fmt.Errorf("wrong checksum length expected 64(sha256) or 128(sha512)")
	}

	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}

	sum := hex.EncodeToString(h.Sum(nil))
	if sum != file.Checksum {
		return true, nil // checksum mismatch file needs fetching
	}
	return false, nil
}

func fetchFromURL(file *types.File) error {
	missing, err := needsFetch(file)
	if err != nil {
		return err
	}

	// exit early if checksum already is correct.
	if !missing {
		return nil
	}

	mode, err := file.FileMode()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, file.URL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	tempFile, err := os.CreateTemp(filepath.Dir(file.Path), "gcm")
	if err != nil {
		return err
	}
	defer tempFile.Close()

	tempFile.Chmod(mode)

	_, err = io.Copy(tempFile, resp.Body)
	if err != nil {
		return err
	}

	if file.ExtractFile != "" {
		tempFile.Seek(0, io.SeekStart)
		newTempFile, err := os.CreateTemp(filepath.Dir(file.Path), "gcm")
		if err != nil {
			return err
		}
		defer newTempFile.Close()
		newTempFile.Chmod(mode)

		err = extractTarGz(tempFile, newTempFile, file.ExtractFile)
		if err != nil {
			return err
		}

		return os.Rename(newTempFile.Name(), file.Path)
	}
	return os.Rename(tempFile.Name(), file.Path)
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
