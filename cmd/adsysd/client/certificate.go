package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/leonelquinteros/gotext"
	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/cmdhandler"
)

// exitError is an error carrying a specific process exit code. It is used by
// the certificate status command so that automation can branch on certificate
// health. When msg is empty the top-level runner exits with the code without
// logging an error.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// ExitCode returns the process exit code associated with the error.
func (e *exitError) ExitCode() int { return e.code }

func (a *App) installCertificate() {
	certCmd := &cobra.Command{
		Use:     "certificate COMMAND",
		Short:   gotext.Get("Certificate management"),
		Aliases: []string{"cert"},
		Args:    cmdhandler.SubcommandsRequiredWithSuggestions,
		RunE:    cmdhandler.NoCmd,
	}

	var listFormat *string
	listCmd := &cobra.Command{
		Use:               "list",
		Short:             gotext.Get("List certificates enrolled by adsys"),
		Args:              cobra.NoArgs,
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE:              func(_ *cobra.Command, _ []string) error { return a.certList(*listFormat) },
	}
	listFormat = listCmd.Flags().StringP("format", "", "text", gotext.Get("output format: text or json."))
	certCmd.AddCommand(listCmd)

	var statusFormat *string
	statusCmd := &cobra.Command{
		Use:   "status [NICKNAME]",
		Short: gotext.Get("Show the health of an enrolled certificate"),
		Long: gotext.Get(`Show the health of an enrolled certificate.
The process exit code reflects the certificate health: 0 healthy, 2 missing,
3 expired, 4 due for renewal, 5 key mismatch or unparseable, 6 not yet valid,
1 on error.`),
		Args:              cmdhandler.ZeroOrNArgs(1),
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			var nickname string
			if len(args) > 0 {
				nickname = args[0]
			}
			return a.certStatus(nickname, *statusFormat)
		},
	}
	statusFormat = statusCmd.Flags().StringP("format", "", "text", gotext.Get("output format: text or json."))
	certCmd.AddCommand(statusCmd)

	var renewAll *bool
	renewCmd := &cobra.Command{
		Use:               "renew [NICKNAME]",
		Short:             gotext.Get("Force re-enrollment of enrolled certificate(s) now"),
		Args:              cmdhandler.ZeroOrNArgs(1),
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			var nickname string
			if len(args) > 0 {
				nickname = args[0]
			}
			return a.certRenew(nickname, *renewAll)
		},
	}
	renewAll = renewCmd.Flags().BoolP("all", "a", false, gotext.Get("renew all enrolled certificates."))
	certCmd.AddCommand(renewCmd)

	var removeAll, removeForce *bool
	removeCmd := &cobra.Command{
		Use:               "remove [NICKNAME]",
		Short:             gotext.Get("Remove enrolled certificate(s) and clean up adsys state"),
		Args:              cmdhandler.ZeroOrNArgs(1),
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			var nickname string
			if len(args) > 0 {
				nickname = args[0]
			}
			return a.certRemove(nickname, *removeAll, *removeForce)
		},
	}
	removeAll = removeCmd.Flags().BoolP("all", "a", false, gotext.Get("remove all enrolled certificates."))
	removeForce = removeCmd.Flags().BoolP("force", "f", false, gotext.Get("confirm removal of certificate material and adsys state."))
	certCmd.AddCommand(removeCmd)

	var verifyOnline *bool
	verifyCmd := &cobra.Command{
		Use:               "verify [NICKNAME]",
		Short:             gotext.Get("Verify chain, validity and key match of enrolled certificate(s)"),
		Args:              cmdhandler.ZeroOrNArgs(1),
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			var nickname string
			if len(args) > 0 {
				nickname = args[0]
			}
			return a.certVerify(nickname, *verifyOnline)
		},
	}
	verifyOnline = verifyCmd.Flags().BoolP("online", "", false, gotext.Get("also perform an online revocation (CRL) check."))
	certCmd.AddCommand(verifyCmd)

	var casFormat *string
	casCmd := &cobra.Command{
		Use:               "cas",
		Short:             gotext.Get("List certificate authorities and templates discovered in AD"),
		Args:              cobra.NoArgs,
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE:              func(_ *cobra.Command, _ []string) error { return a.certCAs(*casFormat) },
	}
	casFormat = casCmd.Flags().StringP("format", "", "text", gotext.Get("output format: text or json."))
	certCmd.AddCommand(casCmd)

	templatesCmd := &cobra.Command{
		Use:               "templates SERVER",
		Short:             gotext.Get("List certificate templates a CA server offers"),
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: cmdhandler.NoValidArgs,
		RunE:              func(_ *cobra.Command, args []string) error { return a.certTemplates(args[0]) },
	}
	certCmd.AddCommand(templatesCmd)

	a.rootCmd.AddCommand(certCmd)
}

// machineTarget returns the short hostname used as the certificate enrollment
// object name, stripping any domain suffix.
func machineTarget() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve client hostname: %w", err)
	}
	target, _, _ := strings.Cut(hostname, ".")
	return target, nil
}

func validateFormat(format string) error {
	switch format {
	case "text", "json":
		return nil
	default:
		return errors.New(gotext.Get("unknown format %q: expected \"text\" or \"json\"", format))
	}
}

func (a *App) certList(format string) error {
	if err := validateFormat(format); err != nil {
		return err
	}
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	target, err := machineTarget()
	if err != nil {
		return err
	}

	stream, err := client.CertList(a.ctx, &adsys.CertTargetRequest{Target: target})
	if err != nil {
		return err
	}

	return renderList(stream.Recv, format,
		func(certs []*adsys.CertInfo) any { return certsToJSON(certs) },
		gotext.Get("No certificates are enrolled by adsys."),
		renderCertText)
}

func (a *App) certStatus(nickname, format string) error {
	if err := validateFormat(format); err != nil {
		return err
	}
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	target, err := machineTarget()
	if err != nil {
		return err
	}

	stream, err := client.CertStatus(a.ctx, &adsys.CertItemRequest{Target: target, Nickname: nickname})
	if err != nil {
		return err
	}

	var info *adsys.CertInfo
	for {
		r, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		info = r
	}
	if info == nil {
		return errors.New(gotext.Get("no enrolled certificate found"))
	}

	if format == "json" {
		if err := outputJSON(certToJSON(info)); err != nil {
			return err
		}
	} else {
		fmt.Print(renderCertText(info))
	}

	if code := exitCodeForHealth(info.GetHealth()); code != 0 {
		return &exitError{code: code}
	}
	return nil
}

func (a *App) certRenew(nickname string, all bool) error {
	if all && nickname != "" {
		return errors.New(gotext.Get("a nickname cannot be used together with --all"))
	}
	if !all && nickname == "" {
		return errors.New(gotext.Get("specify a certificate NICKNAME or use --all"))
	}
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	target, err := machineTarget()
	if err != nil {
		return err
	}

	stream, err := client.CertRenew(a.ctx, &adsys.CertItemRequest{Target: target, Nickname: nickname, All: all})
	if err != nil {
		return err
	}
	return streamMessages(stream)
}

func (a *App) certRemove(nickname string, all, force bool) error {
	if all && nickname != "" {
		return errors.New(gotext.Get("a nickname cannot be used together with --all"))
	}
	if !all && nickname == "" {
		return errors.New(gotext.Get("specify a certificate NICKNAME or use --all"))
	}
	if !force {
		return errors.New(gotext.Get("removing certificate material is destructive; pass --force to confirm"))
	}
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	target, err := machineTarget()
	if err != nil {
		return err
	}

	stream, err := client.CertRemove(a.ctx, &adsys.CertItemRequest{Target: target, Nickname: nickname, All: all, Force: force})
	if err != nil {
		return err
	}
	return streamMessages(stream)
}

func (a *App) certVerify(nickname string, online bool) error {
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	target, err := machineTarget()
	if err != nil {
		return err
	}

	stream, err := client.CertVerify(a.ctx, &adsys.CertItemRequest{Target: target, Nickname: nickname, Online: online})
	if err != nil {
		return err
	}

	var failed bool
	var found bool
	for {
		r, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		found = true
		if !renderVerifyText(r, online) {
			failed = true
		}
	}
	if !found {
		return errors.New(gotext.Get("no enrolled certificate found"))
	}
	if failed {
		return &exitError{code: 1}
	}
	return nil
}

func (a *App) certCAs(format string) error {
	if err := validateFormat(format); err != nil {
		return err
	}
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	target, err := machineTarget()
	if err != nil {
		return err
	}

	stream, err := client.CertListCAs(a.ctx, &adsys.CertTargetRequest{Target: target})
	if err != nil {
		return err
	}

	return renderList(stream.Recv, format,
		func(cas []*adsys.CAInfo) any { return casToJSON(cas) },
		gotext.Get("No certificate authorities were discovered."),
		renderCAText)
}

func (a *App) certTemplates(server string) error {
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	stream, err := client.CertTemplates(a.ctx, &adsys.CertTemplatesRequest{Server: server})
	if err != nil {
		return err
	}
	return streamMessages(stream)
}

// streamMessages prints each StringResponse message from the stream verbatim.
func streamMessages(stream recver) error {
	for {
		r, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		fmt.Print(r.GetMsg())
	}
	return nil
}

// collectStream drains a server stream into a slice.
func collectStream[T any](recv func() (*T, error)) ([]*T, error) {
	var out []*T
	for {
		item, err := recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

// renderList collects a server stream and renders it either as JSON or as text blocks.
func renderList[T any](recv func() (*T, error), format string, toJSON func([]*T) any, emptyMsg string, renderText func(*T) string) error {
	items, err := collectStream(recv)
	if err != nil {
		return err
	}
	if format == "json" {
		return outputJSON(toJSON(items))
	}
	if len(items) == 0 {
		fmt.Println(emptyMsg)
		return nil
	}
	for _, it := range items {
		fmt.Print(renderText(it))
	}
	return nil
}

func exitCodeForHealth(h adsys.CertHealth) int {
	switch h {
	case adsys.CertHealth_CERT_HEALTH_HEALTHY:
		return 0
	case adsys.CertHealth_CERT_HEALTH_MISSING:
		return 2
	case adsys.CertHealth_CERT_HEALTH_EXPIRED:
		return 3
	case adsys.CertHealth_CERT_HEALTH_NOT_YET_VALID:
		return 6
	case adsys.CertHealth_CERT_HEALTH_DUE_RENEWAL:
		return 4
	case adsys.CertHealth_CERT_HEALTH_KEY_MISMATCH, adsys.CertHealth_CERT_HEALTH_UNPARSEABLE:
		return 5
	default:
		return 1
	}
}

func healthString(h adsys.CertHealth) string {
	switch h {
	case adsys.CertHealth_CERT_HEALTH_HEALTHY:
		return "healthy"
	case adsys.CertHealth_CERT_HEALTH_DUE_RENEWAL:
		return "due_renewal"
	case adsys.CertHealth_CERT_HEALTH_EXPIRED:
		return "expired"
	case adsys.CertHealth_CERT_HEALTH_NOT_YET_VALID:
		return "not_yet_valid"
	case adsys.CertHealth_CERT_HEALTH_MISSING:
		return "missing"
	case adsys.CertHealth_CERT_HEALTH_KEY_MISMATCH:
		return "key_mismatch"
	case adsys.CertHealth_CERT_HEALTH_UNPARSEABLE:
		return "unparseable"
	default:
		return "unknown"
	}
}

func yesNo(b bool) string {
	if b {
		return gotext.Get("yes")
	}
	return gotext.Get("no")
}

func renderCertText(info *adsys.CertInfo) string {
	var b strings.Builder
	fmt.Fprintln(&b, gotext.Get("Certificate '%s':", info.GetNickname()))
	fmt.Fprintln(&b, gotext.Get("  status: %s", healthString(info.GetHealth())))
	fmt.Fprintln(&b, gotext.Get("  template: %s", info.GetTemplate()))
	fmt.Fprintln(&b, gotext.Get("  CA: %s (%s)", info.GetCaName(), info.GetCaHostname()))
	fmt.Fprintln(&b, gotext.Get("  subject: %s", info.GetSubject()))
	fmt.Fprintln(&b, gotext.Get("  issuer: %s", info.GetIssuer()))
	if info.GetSerial() != "" {
		fmt.Fprintln(&b, gotext.Get("  serial: %s", info.GetSerial()))
	}
	if info.GetNotAfter() != "" {
		fmt.Fprintln(&b, gotext.Get("  expires: %s (%d days)", info.GetNotAfter(), info.GetDaysUntilExpiry()))
	}
	if len(info.GetSans()) > 0 {
		fmt.Fprintln(&b, gotext.Get("  SANs: %s", strings.Join(info.GetSans(), ", ")))
	}
	if len(info.GetEku()) > 0 {
		fmt.Fprintln(&b, gotext.Get("  EKU: %s", strings.Join(info.GetEku(), ", ")))
	}
	if info.GetKeyAlgo() != "" {
		fmt.Fprintln(&b, gotext.Get("  key: %s %d bits", info.GetKeyAlgo(), info.GetKeySize()))
	}
	fmt.Fprintln(&b, gotext.Get("  key file: %s", info.GetKeyFile()))
	fmt.Fprintln(&b, gotext.Get("  certificate: %s", info.GetCertFile()))
	fmt.Fprintln(&b, gotext.Get("  on disk: %s", yesNo(info.GetOnDisk())))
	fmt.Fprintln(&b, gotext.Get("  key matches certificate: %s", yesNo(info.GetKeyMatchesCert())))
	if info.GetLastEnrolled() != "" {
		fmt.Fprintln(&b, gotext.Get("  last enrolled: %s", info.GetLastEnrolled()))
	}
	return b.String()
}

func renderCAText(ca *adsys.CAInfo) string {
	var b strings.Builder
	fmt.Fprintln(&b, gotext.Get("CA '%s':", ca.GetName()))
	fmt.Fprintln(&b, gotext.Get("  hostname: %s", ca.GetHostname()))
	if len(ca.GetTemplates()) > 0 {
		fmt.Fprintln(&b, gotext.Get("  templates: %s", strings.Join(ca.GetTemplates(), ", ")))
	}
	fmt.Fprintln(&b, gotext.Get("  installed in trust store: %s", yesNo(ca.GetInstalledInTrust())))
	fmt.Fprintln(&b, gotext.Get("  enrolled: %s", yesNo(ca.GetEnrolled())))
	return b.String()
}

// renderVerifyText prints one verification result and returns whether it
// succeeded.
//
// A revocation check that was requested but did not complete - no CRL
// distribution point, an unreachable, stale or untrusted CRL - leaves the
// revocation state unknown. Reporting that as PASS would present an
// indeterminate result as a clean one, so it is reported as UNKNOWN and, like a
// failure, exits nonzero.
func renderVerifyText(r *adsys.CertVerifyResult, online bool) bool {
	ok := r.GetChainOk() && r.GetValidityOk() && r.GetKeyMatchOk() && !r.GetRevoked()
	result := gotext.Get("PASS")
	switch {
	case !ok:
		result = gotext.Get("FAIL")
	case online && !r.GetRevocationChecked():
		ok = false
		result = gotext.Get("UNKNOWN")
	}
	fmt.Println(gotext.Get("Certificate '%s': %s", r.GetNickname(), result))
	fmt.Println(gotext.Get("  chain: %s", yesNo(r.GetChainOk())))
	fmt.Println(gotext.Get("  validity: %s", yesNo(r.GetValidityOk())))
	fmt.Println(gotext.Get("  key matches certificate: %s", yesNo(r.GetKeyMatchOk())))
	switch {
	case r.GetRevocationChecked():
		fmt.Println(gotext.Get("  revoked: %s", yesNo(r.GetRevoked())))
	case online:
		fmt.Println(gotext.Get("  revoked: %s", gotext.Get("unknown")))
	}
	for _, m := range r.GetMessages() {
		fmt.Println(gotext.Get("  - %s", m))
	}
	return ok
}

// JSON rendering. Local structs keep the output stable and independent of the
// protobuf wire representation.

type certJSON struct {
	Nickname        string   `json:"nickname"`
	Template        string   `json:"template"`
	CA              string   `json:"ca"`
	CAHostname      string   `json:"ca_hostname"`
	Subject         string   `json:"subject"`
	Issuer          string   `json:"issuer"`
	Serial          string   `json:"serial"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	DaysUntilExpiry int64    `json:"days_until_expiry"`
	SANs            []string `json:"sans"`
	EKU             []string `json:"eku"`
	KeyAlgo         string   `json:"key_algo"`
	KeySize         int64    `json:"key_size"`
	KeyFile         string   `json:"key_file"`
	CertFile        string   `json:"cert_file"`
	RootCertFiles   []string `json:"root_cert_files"`
	TrustSymlinks   []string `json:"trust_symlinks"`
	OnDisk          bool     `json:"on_disk"`
	KeyMatchesCert  bool     `json:"key_matches_cert"`
	Health          string   `json:"health"`
	LastEnrolled    string   `json:"last_enrolled"`
}

func certToJSON(info *adsys.CertInfo) certJSON {
	return certJSON{
		Nickname:        info.GetNickname(),
		Template:        info.GetTemplate(),
		CA:              info.GetCaName(),
		CAHostname:      info.GetCaHostname(),
		Subject:         info.GetSubject(),
		Issuer:          info.GetIssuer(),
		Serial:          info.GetSerial(),
		NotBefore:       info.GetNotBefore(),
		NotAfter:        info.GetNotAfter(),
		DaysUntilExpiry: info.GetDaysUntilExpiry(),
		SANs:            info.GetSans(),
		EKU:             info.GetEku(),
		KeyAlgo:         info.GetKeyAlgo(),
		KeySize:         info.GetKeySize(),
		KeyFile:         info.GetKeyFile(),
		CertFile:        info.GetCertFile(),
		RootCertFiles:   info.GetRootCertFiles(),
		TrustSymlinks:   info.GetTrustSymlinks(),
		OnDisk:          info.GetOnDisk(),
		KeyMatchesCert:  info.GetKeyMatchesCert(),
		Health:          healthString(info.GetHealth()),
		LastEnrolled:    info.GetLastEnrolled(),
	}
}

func certsToJSON(certs []*adsys.CertInfo) []certJSON {
	out := make([]certJSON, 0, len(certs))
	for _, c := range certs {
		out = append(out, certToJSON(c))
	}
	return out
}

type caJSON struct {
	Name             string   `json:"name"`
	Hostname         string   `json:"hostname"`
	Templates        []string `json:"templates"`
	RootFingerprints []string `json:"root_fingerprints"`
	InstalledInTrust bool     `json:"installed_in_trust"`
	Enrolled         bool     `json:"enrolled"`
}

func casToJSON(cas []*adsys.CAInfo) []caJSON {
	out := make([]caJSON, 0, len(cas))
	for _, ca := range cas {
		out = append(out, caJSON{
			Name:             ca.GetName(),
			Hostname:         ca.GetHostname(),
			Templates:        ca.GetTemplates(),
			RootFingerprints: ca.GetRootFingerprints(),
			InstalledInTrust: ca.GetInstalledInTrust(),
			Enrolled:         ca.GetEnrolled(),
		})
	}
	return out
}

func outputJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
