package reconciliation

import (
	"fmt"
	"strings"

	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/sirupsen/logrus"
)

// Only yum for now.
func (mr *MachineReconciler) packages(packages types.Packages) {
	for _, pkg := range packages {
		err := mr.installPackage(pkg)
		if err != nil {
			logrus.Errorf("package: installing %s@%s: %s", pkg.Name, pkg.Version, err)
			continue
		}
	}
}

func (mr *MachineReconciler) installPackage(pkg *types.Package) error {
	name := pkg.Name + "-" + pkg.Version
	if pkg.Version == "*" || pkg.Version == "" {
		name = pkg.Name
	}

	_, c, err := mr.commander.RunExpectCodes(fmt.Sprintf("rpm -q %s", name), 0, 1)
	if err != nil {
		return err
	}
	if c == 0 {
		return nil
	}
	// also check provides if you are installing for example vim which provides vim-enhanced package.
	providedBy, _, err := mr.commander.Run(fmt.Sprintf("rpm -q --whatprovides %s", name))
	if err != nil {
		return err
	}

	_, _, err = mr.commander.Run(fmt.Sprintf("yum install -y %s", strings.TrimSpace(providedBy)))
	return err
}
