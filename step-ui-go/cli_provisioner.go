package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"step-ui/config"
	appdb "step-ui/db"
)

func runProvisionerCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: step-ui provisioner-register|provisioner-list")
	}
	switch args[0] {
	case "provisioner-register":
		return runProvisionerRegister(args[1:])
	case "provisioner-list":
		return runProvisionerList()
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runProvisionerRegister(args []string) error {
	fs := flag.NewFlagSet("provisioner-register", flag.ContinueOnError)
	name := fs.String("name", "", "provisioner name")
	typ := fs.String("type", "JWK", "provisioner type")
	defDur := fs.String("default-dur", "8760h", "default TLS duration")
	maxDur := fs.String("max-dur", "87600h", "max TLS duration")
	pwFile := fs.String("password-file", "", "password file or - for stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	password, err := readCLIPassword(*pwFile)
	if err != nil {
		return err
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("provisioner password is required")
	}
	cfg := config.Load()
	conn, err := appdb.Connect(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := appdb.InitSchema(conn); err != nil {
		return err
	}
	if err := appdb.RegisterCAProvisioner(conn, *name, *typ, *defDur, *maxDur, password, cfg.SecretKey, cfg.Provisioner); err != nil {
		return err
	}
	fmt.Printf("registered provisioner %s (JWK default=%s max=%s)\n", *name, *defDur, *maxDur)
	return nil
}

func runProvisionerList() error {
	cfg := config.Load()
	conn, err := appdb.Connect(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := appdb.InitSchema(conn); err != nil {
		return err
	}
	list, err := appdb.ListCAProvisioners(conn)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTYPE\tDEFAULT\tMAX\tSYSTEM")
	for _, p := range list {
		sys := "no"
		if p.IsSystem {
			sys = "yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", p.Name, p.Type, p.DefaultDuration, p.MaxDuration, sys)
	}
	return w.Flush()
}

func readCLIPassword(path string) (string, error) {
	if path == "" || path == "-" {
		b, err := io.ReadAll(bufio.NewReader(os.Stdin))
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return appdb.ReadProvisionerPasswordFile(path)
}
