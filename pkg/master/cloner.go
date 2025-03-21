package master

import (
	"context"
	"net/url"
	"os"
	"path/filepath"

	"github.com/fluxcd/pkg/git"
	"github.com/fluxcd/pkg/git/repository"
	"github.com/sirupsen/logrus"
)

type Cloner interface {
	Clone(ctx context.Context, url string, cloneOpts repository.CloneConfig) (*git.Commit, error)
	Close()
}

type testCloner struct {
	dir string
}

func (tc *testCloner) Clone(ctx context.Context, URL string, cloneOpts repository.CloneConfig) (*git.Commit, error) {

	u, err := url.Parse(URL)
	if err != nil {
		return nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	from := filepath.Join(cwd, u.Path)
	logrus.Infof("testCloner: copy %s to %s", from, tc.dir)
	err = os.CopyFS(tc.dir, os.DirFS(from))
	return nil, err
}
func (tc *testCloner) Close() {

}
