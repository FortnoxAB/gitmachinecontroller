package reconciliation

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/fortnoxab/gitmachinecontroller/mocks"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestFilesContentWithSystemd(t *testing.T) {
	machine := &types.Machine{
		Spec: &types.Spec{
			Tasks: types.Tasks{
				{
					Files: types.Files{
						&types.File{
							Path:    "testfil1",
							Content: "test",
							Systemd: &types.SystemdReference{
								DaemonReload: true,
								Name:         "service1",
								Action:       "restart",
							},
						},
					},
				},
			},
		},
	}
	defer os.Remove("testfil1")

	mockedCommander := mocks.NewMockCommander(t)
	mockedCommander.Mock.On("Run", "systemctl restart service1").Return("", "", nil).Once()
	mockedCommander.Mock.On("Run", "systemctl daemon reload").Return("", "", nil).Once()

	recon := NewMachineReconciler(mockedCommander, nil) //TODO no redis in those tests yet. Its tested in e2e
	err := recon.Reconcile(machine)
	assert.NoError(t, err)

	assert.FileExists(t, "testfil1")
	c, err := os.ReadFile("testfil1")
	assert.NoError(t, err)
	assert.EqualValues(t, c, "test")

	// assert nothing changes if we run it again

	err = recon.Reconcile(machine)
	assert.NoError(t, err)
	c, err = os.ReadFile("testfil1")
	assert.NoError(t, err)
	assert.EqualValues(t, c, "test")

}
func TestFilesContentChanged(t *testing.T) {
	machine := &types.Machine{
		Spec: &types.Spec{
			Tasks: types.Tasks{
				{
					Files: types.Files{
						&types.File{
							Path:    "testfil1",
							Content: "test",
						},
					},
				},
			},
		},
	}
	defer os.Remove("testfil1")

	mockedCommander := mocks.NewMockCommander(t)

	recon := NewMachineReconciler(mockedCommander, nil) //TODO no redis in those tests yet. Its tested in e2e
	err := recon.Reconcile(machine)
	assert.NoError(t, err)

	assert.FileExists(t, "testfil1")
	c, err := os.ReadFile("testfil1")
	assert.NoError(t, err)
	assert.EqualValues(t, "test", string(c))

	machine.Spec.Tasks[0].Files[0].Content = "newlongercontent"

	err = recon.Reconcile(machine)
	assert.NoError(t, err)
	c, err = os.ReadFile("testfil1")
	assert.NoError(t, err)
	assert.EqualValues(t, "newlongercontent", string(c))
}
func TestFilesContentChangedWithEqualSize(t *testing.T) {
	machine := &types.Machine{
		Spec: &types.Spec{
			Tasks: types.Tasks{
				{
					Files: types.Files{
						&types.File{
							Path:    "testfil1",
							Content: "test",
						},
					},
				},
			},
		},
	}
	defer os.Remove("testfil1")

	mockedCommander := mocks.NewMockCommander(t)

	recon := NewMachineReconciler(mockedCommander, nil) //TODO no redis in those tests yet. Its tested in e2e
	err := recon.Reconcile(machine)
	assert.NoError(t, err)

	assert.FileExists(t, "testfil1")
	c, err := os.ReadFile("testfil1")
	assert.NoError(t, err)
	assert.EqualValues(t, "test", string(c))

	machine.Spec.Tasks[0].Files[0].Content = "tes1"

	err = recon.Reconcile(machine)
	assert.NoError(t, err)
	c, err = os.ReadFile("testfil1")
	assert.NoError(t, err)
	assert.EqualValues(t, "tes1", string(c))
}

func testGzFile() []byte {
	/*
			tar.gz file with this structure:
		   ./
		   ./folder/
		   ./folder/test2
		   ./test1
	*/
	s, _ := base64.StdEncoding.DecodeString(`H4sIAAAAAAAAA+3TQQqDMBCF4ax7Ck+gmcToecTqohUFTe9flbZgKS0uokj/bzOggQy8vDhRwelRnutpSu4W80lJOp5wkqYuVVqMsVZFLvxqSt0GX/RRpC5dWwx10ZTXz+d+/T+oOKm75lz1IZ/BqvwzO+Zvnc7Ifwuv/H01eBPmjingLPuSv8hb/vOIdJh1lv48/7JrfdV6c9p7EewinosvQe9Y1f/pu1ij6f8mHv0X+g8AAAAAAAAAAAAAx3YHfKjFYAAoAAA=`)
	return s
}

func TestFilesContent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "the file content")
	}))
	defer ts.Close()

	tarGz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(testGzFile())
		assert.NoError(t, err)
	}))
	defer tarGz.Close()
	var tests = []struct {
		name                 string
		expectedContent      string
		expectedErrorContain string
		given                *types.File
	}{
		// download url
		{
			name:                 "URL: test wrong checksum length",
			expectedContent:      "",
			expectedErrorContain: "wrong checksum length expected",
			given: &types.File{
				Path: "testfil1",
				URL:  ts.URL,
			},
		},
		{
			name:                 "URL: test download URL wrong checksum",
			expectedContent:      "",
			expectedErrorContain: "checksum mismatch.",
			given: &types.File{
				Path:     "testfil1",
				URL:      ts.URL,
				Checksum: "9b76e7ea790545334ea524f3ca33db8eb6c4541a9b476911e5abf850a566b411",
			},
		},
		{
			name:            "URL: test download",
			expectedContent: "the file content",
			given: &types.File{
				Path:     "testfil1",
				URL:      ts.URL,
				Checksum: "9b76e7ea790545334ea524f3ca33db8eb6c4541a9b476911e5abf850a566b41c",
			},
		},

		// tar.gz
		{
			name:                 "tar.gz: test wrong checksum length",
			expectedContent:      "",
			expectedErrorContain: "wrong checksum length expected",
			given: &types.File{
				Path:        "testfil1",
				URL:         tarGz.URL,
				ExtractFile: "test1",
			},
		},
		{
			name:                 "tar.gz: test download wrong checksum",
			expectedContent:      "",
			expectedErrorContain: "checksum mismatch.",
			given: &types.File{
				Path:        "testfil1",
				URL:         tarGz.URL,
				Checksum:    "9b76e7ea790545334ea524f3ca33db8eb6c4541a9b476911e5abf850a566b411",
				ExtractFile: "test1",
			},
		},
		{
			name:            "tar.gz: test download",
			expectedContent: "content1\n",
			given: &types.File{
				Path:        "testfil1",
				URL:         tarGz.URL,
				Checksum:    "47d741b6059c6d7e99be25ce46fb9ba099cfd6515de1ef7681f93479d25996a4",
				ExtractFile: "test1",
			},
		},
		{
			name:            "tar.gz: test download extract subpath",
			expectedContent: "content2\n",
			given: &types.File{
				Path:        "testfil1",
				URL:         tarGz.URL,
				Checksum:    "e0763097d2327a89fb7fc6a1fad40f87d2261dcdd6c09e65ee00b200a0128e1c",
				ExtractFile: "folder/test2",
			},
		},
		// content
		{
			name:            "test content",
			expectedContent: "test content",
			// expectedErrorContain: "wrong checksum length expected",
			given: &types.File{
				Path:    "testfil1",
				Content: "test content",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			machine := &types.Machine{
				Spec: &types.Spec{
					Tasks: types.Tasks{
						{
							Files: types.Files{
								tt.given,
							},
						},
					},
				},
			}
			defer os.Remove("testfil1")

			mockedCommander := mocks.NewMockCommander(t)

			recon := NewMachineReconciler(mockedCommander, nil) //TODO no redis in those tests yet. Its tested in e2e
			buf := &bytes.Buffer{}
			logrus.SetFormatter(&logrus.TextFormatter{
				DisableColors: true,
			})
			logrus.SetOutput(buf)
			err := recon.Reconcile(machine)
			assert.NoError(t, err)

			if tt.expectedErrorContain != "" {
				assert.Contains(t, buf.String(), tt.expectedErrorContain)
				return
			}

			fmt.Println("log was", buf.String())

			assert.FileExists(t, "testfil1")
			c, err := os.ReadFile("testfil1")
			assert.NoError(t, err)
			assert.EqualValues(t, tt.expectedContent, string(c))

			// assert nothing changes if we run it again

			err = recon.Reconcile(machine)
			assert.NoError(t, err)
			c, err = os.ReadFile("testfil1")
			assert.NoError(t, err)
			assert.EqualValues(t, tt.expectedContent, string(c))
		})
	}

	m, err := filepath.Glob("./gmc*")
	assert.NoError(t, err)
	assert.Empty(t, m, "assert all temp files are removed")
}

/* //TODO test owner how? in a container?
func TestFilesUserGroup(t *testing.T) {
	machine := &types.Machine{
		Spec: &types.Spec{
			Tasks: types.Tasks{
				{
					Files: types.Files{
						&types.File{
							Path:    "testfil1",
							Content: "test",
							User:    "nobody",
							Group:   "nogroup",
							Systemd: &types.SystemdReference{
								DaemonReload: true,
								Name:         "service1",
								Action:       "restart",
							},
						},
					},
				},
			},
		},
	}
	// defer os.Remove("testfil1")

	mockedCommander := mocks.NewMockCommander(t)
	mockedCommander.Mock.On("Run", "systemctl restart service1").Return("", "", nil).Once()
	mockedCommander.Mock.On("Run", "systemctl daemon reload").Return("", "", nil).Once()

	recon := NewMachineReconciler(mockedCommander, nil)
	err := recon.Reconcile(machine)
	assert.NoError(t, err)

	assert.FileExists(t, "testfil1")
	c, err := os.ReadFile("testfil1")
	assert.NoError(t, err)
	assert.EqualValues(t, c, "test")

	file, err := os.Stat("testfil1")
	assert.NoError(t, err)
	stat, ok := file.Sys().(*syscall.Stat_t)
	if !ok {
		t.Error("not syscall.Stat_t")
	}
	assert.Equal(t, "nobody", int(stat.Uid))

}
*/

func TestInstallPackages(t *testing.T) {

	var tests = []struct {
		name           string
		packageName    string
		packageVersion string
		providesIt     string
		mock           func(*mocks.MockCommander)
	}{
		{
			name:           "provided by other",
			packageName:    "vim",
			packageVersion: "*",
			providesIt:     "vim-enhanced-8.0.1763-19.el8_6.4.x86_64",
		},
		{
			name:           "provided by same",
			packageName:    "nano",
			packageVersion: "*",
			providesIt:     "nano",
		},
		{
			name:           "already installed",
			packageName:    "nano",
			packageVersion: "*",
			mock: func(m *mocks.MockCommander) {
				m.Mock.On("RunExpectCodes", "rpm -q nano", 0, 1).Return("", 0, nil).Once()
			},
		},
		{
			name:           "rpm error",
			packageName:    "nano",
			packageVersion: "*",
			mock: func(m *mocks.MockCommander) {
				m.Mock.On("RunExpectCodes", "rpm -q nano", 0, 1).Return("", 10, fmt.Errorf("error from rpm")).Once()
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			machine := &types.Machine{
				Spec: &types.Spec{
					Tasks: types.Tasks{
						{
							Packages: types.Packages{
								{
									Name:    tt.packageName,
									Version: tt.packageVersion,
								},
							},
						},
					},
				},
			}

			mockedCommander := mocks.NewMockCommander(t)
			if tt.mock != nil {
				tt.mock(mockedCommander)
			} else {
				mockedCommander.Mock.On("RunExpectCodes", fmt.Sprintf("rpm -q %s", tt.packageName), 0, 1).Return("", 1, nil).Once()
				mockedCommander.Mock.On("Run", fmt.Sprintf("rpm -q --whatprovides %s", tt.packageName)).Return(tt.providesIt, "", nil).Once()
				mockedCommander.Mock.On("Run", fmt.Sprintf("yum install -y %s", tt.providesIt)).Return("", "", nil).Once()
			}

			recon := NewMachineReconciler(mockedCommander, nil)
			err := recon.Reconcile(machine)
			assert.NoError(t, err)
		})
	}

}
