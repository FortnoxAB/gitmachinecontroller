package reconciliation

import (
	"fmt"

	"github.com/fortnoxab/gitmachinecontroller/pkg/agent/command"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/sirupsen/logrus"
)

// Only yum for now.
func (mr *MachineReconciler) packages(packages types.Packages) error {
	for _, pkg := range packages {
		err := installPackage(pkg)
		if err != nil {
			logrus.Errorf("package: installing %s@%s: %s", pkg.Name, pkg.Version, err)
			continue
		}
	}
	return nil
}

func installPackage(pkg *types.Package) error {
	name := pkg.Name + "-" + pkg.Version
	if pkg.Version == "*" || pkg.Version == "" {
		name = pkg.Name
	}

	_, c, err := command.RunExpectCodes(fmt.Sprintf("rpm -q %s", name), 0, 1)
	if err != nil {
		return err
	}
	if c == 0 {
		return nil
	}
	// also check provides if you are installing for example vim which provides vim-enhanced package.
	_, c, err = command.RunExpectCodes(fmt.Sprintf("rpm -q --whatprovides %s", name), 0, 1)
	if err != nil {
		return err
	}
	if c == 0 {
		return nil
	}

	_, _, err = command.Run(fmt.Sprintf("yum install -y %s", name))
	return err
}
