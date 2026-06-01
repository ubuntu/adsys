// Package main implements the adsys-certsubmit certmonger helper binary.
//
// This binary acts as a certificate submission helper for certmonger.
// When certmonger needs to submit a CSR to a CA, it invokes this helper
// with environment variables describing the operation to perform.
//
// Supported operations:
//   - SUBMIT: Submit a CSR to AD CS via MS-ICPR (RPC) and return the certificate
//   - IDENTIFY: Return the helper's identity string
//   - GET-SUPPORTED-TEMPLATES: Return templates supported by the CA
//
// The helper uses Kerberos authentication (via the KRB5CCNAME env var)
// to authenticate to AD CS.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ubuntu/adsys/internal/policies/certificate"
)

func main() {
	server := flag.String("server", "", "AD CS server hostname")
	ca := flag.String("ca", "", "CA common name (Authority)")
	operationFlag := flag.String("operation", "", "Operation to perform when invoked manually")
	csrFile := flag.String("csr-file", "", "Path to a PEM CSR when invoked manually")
	templateFlag := flag.String("template", "", "Certificate template name when invoked manually")
	flag.Parse()

	operation := os.Getenv("CERTMONGER_OPERATION")
	if operation == "" {
		operation = *operationFlag
	}

	switch strings.ToUpper(operation) {
	case "IDENTIFY":
		fmt.Println("adsys-certsubmit")
		os.Exit(0)

	case "SUBMIT":
		if *server == "" {
			fmt.Fprintln(os.Stderr, "error: --server is required for SUBMIT operation")
			os.Exit(2)
		}
		caName := certmongerCAName(*ca)
		if caName == "" {
			fmt.Fprintln(os.Stderr, "error: --ca or CERTMONGER_CA_NICKNAME is required for SUBMIT operation")
			os.Exit(2)
		}
		csr := os.Getenv("CERTMONGER_CSR")
		if csr == "" {
			if *csrFile == "" {
				fmt.Fprintln(os.Stderr, "error: CERTMONGER_CSR environment variable is not set")
				os.Exit(2)
			}
			data, err := os.ReadFile(*csrFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: reading CSR file: %v\n", err)
				os.Exit(2)
			}
			csr = string(data)
		}

		template := os.Getenv("CERTMONGER_CA_PROFILE")
		if template == "" {
			template = *templateFlag
		}

		certPEM, err := certificate.SubmitCSR(context.Background(), *server, caName, template, csr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}

		fmt.Print(certPEM)
		os.Exit(0)

	case "GET-SUPPORTED-TEMPLATES":
		if *server == "" {
			fmt.Fprintln(os.Stderr, "error: --server is required for GET-SUPPORTED-TEMPLATES operation")
			os.Exit(2)
		}
		templates, err := certificate.GetSupportedTemplates(*server)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		for _, t := range templates {
			fmt.Println(t)
		}
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "unsupported operation: %s\n", operation)
		os.Exit(6) // certmonger convention: 6 = unsupported operation
	}
}

func certmongerCAName(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	for _, env := range []string{"CERTMONGER_CA_NICKNAME", "CERTMONGER_CA_NAME"} {
		if value := os.Getenv(env); value != "" {
			return value
		}
	}
	return ""
}
