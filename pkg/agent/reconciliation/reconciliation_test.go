package reconciliation

import (
	"fmt"
	"os"
	"testing"

	"github.com/fortnoxab/gitmachinecontroller/mocks"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/stretchr/testify/assert"
)

func TestFilesContent(t *testing.T) {

	machine := &types.Machine{
		Spec: &types.Spec{
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
	}
	defer os.Remove("testfil1")

	mockedCommander := mocks.NewMockCommander(t)
	mockedCommander.Mock.On("Run", "systemctl restart service1").Return("", "", nil).Once()
	mockedCommander.Mock.On("Run", "systemctl daemon reload").Return("", "", nil).Once()

	recon := NewMachineReconciler(mockedCommander)
	err := recon.Reconcile(machine)
	assert.NoError(t, err)

	assert.FileExists(t, "testfil1")
	c, err := os.ReadFile("testfil1")
	assert.NoError(t, err)
	assert.EqualValues(t, c, "test")
}

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
					Packages: types.Packages{
						{
							Name:    tt.packageName,
							Version: tt.packageVersion,
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

			recon := NewMachineReconciler(mockedCommander)
			err := recon.Reconcile(machine)
			assert.NoError(t, err)
		})
	}

}
