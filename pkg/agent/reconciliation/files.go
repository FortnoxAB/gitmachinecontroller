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
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/sirupsen/logrus"
)

func (mr *MachineReconciler) files(files types.Files) {
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
}

// assertSameOwner returns a bool if it was changed
func assertSameOwner(file os.FileInfo, fileSpec *types.File) (bool, error) {
	if fileSpec.User == "" && fileSpec.Group == "" {
		return false, nil
	}
	var existingFileUid int
	var existingFileGid int
	stat, ok := file.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("not syscall.Stat_t")
	}
	existingFileUid = (int(stat.Uid))
	existingFileGid = (int(stat.Gid))
	u, err := user.Lookup(fileSpec.User)
	if err != nil {
		return false, err
	}
	g, err := user.LookupGroup(fileSpec.User)
	if err != nil {
		return false, err
	}

	newUid, _ := strconv.Atoi(u.Uid)
	newGid, _ := strconv.Atoi(g.Gid)

	if existingFileUid == newUid && existingFileGid == newGid {
		return false, nil
	}

	return true, os.Chown(fileSpec.Path, newUid, newGid)
}
func chown(file *os.File, userName, group string) error {
	if userName == "" && group == "" {
		return nil
	}
	u, err := user.Lookup(userName)
	if err != nil {
		return err
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return err
	}

	newUid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	newGid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}
	return file.Chown(newUid, newGid)
}
func chownName(file, userName, group string) error {
	if userName == "" && group == "" {
		return nil
	}
	u, err := user.Lookup(userName)
	if err != nil {
		return err
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return err
	}

	newUid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	newGid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}
	return os.Chown(file, newUid, newGid)
}

func writeContentIfNeeded(file *types.File) (bool, error) {
	newMode, err := file.FileMode()
	if err != nil {
		return false, err
	}

	statedFile, err := os.Stat(file.Path)
	if errors.Is(err, os.ErrNotExist) { // New file we can write directly to desired location
		err = os.WriteFile(file.Path, []byte(file.Content), newMode)
		if err != nil {
			return false, err
		}
		err = chownName(file.Path, file.User, file.Group)
		if err != nil {
			return true, err
		}
		return true, nil
	}

	equal := false
	if int64(len(file.Content)) == statedFile.Size() { // we only need to do expensive fileEqual if size are the same
		equal, err = fileEqual(file.Content, file.Path)
		if err != nil {
			return false, err
		}
	}
	if equal {
		var changedMode bool
		if newMode != statedFile.Mode() { // check if content was same but we need to update newMode
			err = os.Chmod(file.Path, newMode)
			if err != nil {
				return false, err
			}
			changedMode = true
		}
		var changedOwner bool
		changedOwner, err = assertSameOwner(statedFile, file)
		if err != nil {
			return false, err
		}

		logrus.Debug(file.Path, " already equal")
		return changedOwner || changedMode, nil
	}

	// existing file we make a tempfile in the same target directory and then atomic move.
	tempFile, err := os.CreateTemp(filepath.Dir(file.Path), "gmc")
	if err != nil {
		return false, err
	}
	defer tempFile.Close()
	err = tempFile.Chmod(newMode)
	if err != nil {
		return false, err
	}

	err = chown(tempFile, file.User, file.Group)
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
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil // file does not exist it needs fetching
		}
		return false, err
	}
	defer f.Close()

	equal, err := hashIsEqual(f, file.Checksum)
	if err != nil {
		return false, err
	}

	return !equal, nil
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
	shouldFetch, err := needsFetch(file)
	if err != nil {
		return false, err
	}

	// exit early if checksum already is correct. But assert chmod and chown
	if !shouldFetch {
		var newMode os.FileMode
		newMode, err = file.FileMode()
		if err != nil {
			return false, err
		}

		var statedFile os.FileInfo
		statedFile, err = os.Stat(file.Path)
		if err != nil {
			return false, err
		}

		var changedMode bool
		var changedOwner bool
		if newMode != statedFile.Mode() { // check if content was same but we need to update newMode
			err = os.Chmod(file.Path, newMode)
			if err != nil {
				return false, err
			}
			changedMode = true
		}
		changedOwner, err = assertSameOwner(statedFile, file)
		if err != nil {
			return false, err
		}
		return changedMode || changedOwner, nil
	}

	newMode, err := file.FileMode()
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
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

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
		defer os.Remove(newTempFile.Name())
		defer newTempFile.Close()

		err = extractTarGz(tempFile, newTempFile, file.ExtractFile)
		if err != nil {
			return false, err
		}

		tempFile.Close()
		tempFile = newTempFile
	}

	tempFile.Seek(0, io.SeekStart)
	equal, err := hashIsEqual(tempFile, file.Checksum)
	if err != nil {
		return false, err
	}
	if !equal {
		return false, fmt.Errorf("checksum mismatch. expected file to be %s", file.Checksum)
	}
	err = tempFile.Chmod(newMode)
	if err != nil {
		return false, err
	}
	err = chown(tempFile, file.User, file.Group)
	if err != nil {
		return false, err
	}
	tempFile.Close() // close so we can move it
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
		case tar.TypeDir: //TODO support entire folder extracts?
			// if err := os.Mkdir(header.Name, 0755); err != nil {
			// 	log.Fatalf("ExtractTarGz: Mkdir() failed: %s", err.Error())
			// }
		case tar.TypeReg:
			if filepath.Clean(header.Name) != singleFile {
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
