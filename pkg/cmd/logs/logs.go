package logs

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/config"
	"github.com/ibm-verify/verifyctl/pkg/module/logs"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	usage         = "logs [flags]"
	messagePrefix = "Logs"
	entitlements  = "Read trace logs (readTraceLogs)"
)

var (
	longDesc = templates.LongDesc(cmdutil.TranslateLongDesc(messagePrefix, `
		Print logs from your Verify tenant.
		
Verify APIs require specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl logs --entitlements`))

	examples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Tail logs from Verify.
		verifyctl logs --follow`))

	entitlementsMessage = i18n.Translate("Choose any of the following entitlements to configure your application or API client:\n")
)

type options struct {
	follow       bool
	filter       string
	severity     string
	spanID       string
	traceID      string
	entitlements bool

	config *config.CLIConfig
}

func NewCommand(config *config.CLIConfig, streams io.ReadWriter, groupID string) *cobra.Command {
	o := &options{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   usage,
		Short:                 cmdutil.TranslateShortDesc(messagePrefix, "Print logs from your Verify tenant."),
		Long:                  longDesc,
		Example:               examples,
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.ExitOnError(cmd, o.Complete(cmd, args))
			cmdutil.ExitOnError(cmd, o.Validate(cmd, args))
			cmdutil.ExitOnError(cmd, o.Run(cmd, args))
		},
		GroupID: groupID,
	}

	cmd.SetOut(streams)
	cmd.SetErr(streams)
	cmd.SetIn(streams)

	o.AddFlags(cmd)
	return cmd
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&o.follow, "follow", "f", false, i18n.Translate("Indicate that the logs should be continuously printed until the process is terminated using, for example, Ctrl-C."))
	cmd.Flags().StringVar(&o.filter, "filter", "", i18n.Translate("Search filter when querying logs."))
	cmd.Flags().StringVar(&o.spanID, "span", "", i18n.Translate("SpanID property to filter."))
	cmd.Flags().StringVar(&o.traceID, "trace", "", i18n.Translate("TraceID property to filter."))
	cmd.Flags().StringVarP(&o.severity, "severity", "s", "", i18n.Translate("Severity of logs."))
	cmd.Flags().BoolVar(&o.entitlements, "entitlements", o.entitlements, i18n.Translate("List the entitlements that can be configured to allow this operation. This is useful to know what to configure on the application or API client used to generate the login token. When this flag is used, the others are ignored."))
}

func (o *options) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *options) Validate(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+entitlements)
		return nil
	}

	auth, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	c := logs.NewLogsClient()
	err = c.PrintLogs(cmd.Context(), auth, cmd.OutOrStdout(), &logs.LogParameters{
		SpanID:   o.spanID,
		TraceID:  o.traceID,
		Filter:   o.filter,
		Severity: o.severity,
		Follow:   o.follow,
	})

	if err != nil {
		return err
	}

	return nil
}
