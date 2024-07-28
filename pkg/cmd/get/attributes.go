package get

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vivshankar/verifyctl/pkg/client"
	"github.com/vivshankar/verifyctl/pkg/config"
	"github.com/vivshankar/verifyctl/pkg/i18n"
	cmdutil "github.com/vivshankar/verifyctl/pkg/util/cmd"
	"github.com/vivshankar/verifyctl/pkg/util/templates"
)

const (
	attributesUsage         = `attributes [flags]`
	attributesMessagePrefix = "GetAttributes"
	attributesEntitlements  = "Manage attributes"
)

var (
	attributesLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(attributesMessagePrefix, `
		Get Verify attributes based on an optional filter or a specific attribute.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl get attributes --entitlements`))

	attributesExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Get an attribute and write it to a file
		verifyctl get attribute --outfile ./work_email.yaml --id=work_email

		# Get all attributes that match department "2A". There may be limits introduced by the API.
		verifyctl get users --filter="urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq \"2A\"" --attributes="userName,emails,urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager" -o yaml`))
)

type attributesOptions struct {
	OutputType   string
	OutputFile   string
	Entitlements bool
	ID           string
	Filter       string

	config *config.CLIConfig
}

func NewAttributesCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &attributesOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   attributesUsage,
		Short:                 cmdutil.TranslateShortDesc(messagePrefix, "Get Verify attributes based on an optional filter or a specific attribute."),
		Long:                  attributesLongDesc,
		Example:               attributesExamples,
		Aliases:               []string{"attribute", "attributes"},
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.ExitOnError(cmd, o.Complete(cmd, args))
			cmdutil.ExitOnError(cmd, o.Validate(cmd, args))
			cmdutil.ExitOnError(cmd, o.Run(cmd, args))
		},
	}

	cmd.SetOut(streams)
	cmd.SetErr(streams)
	cmd.SetIn(streams)

	o.AddFlags(cmd)

	return cmd
}

func (o *attributesOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.ID, "id", "", i18n.Translate("Attribute identifier or name."))
	cmd.Flags().StringVar(&o.Filter, "filter", "", i18n.Translate("Search filter when fetching multiple attributes."))
}

func (o *attributesOptions) Complete(cmd *cobra.Command, args []string) error {
	o.Entitlements = cmd.Flag("entitlements").Changed
	o.OutputType = cmd.Flag("output").Value.String()
	o.OutputFile = cmd.Flag("outfile").Value.String()
	if len(o.OutputType) == 0 && len(o.OutputFile) > 0 {
		if strings.HasSuffix(o.OutputFile, ".json") {
			o.OutputType = "json"
		}
	}
	return nil
}

func (o *attributesOptions) Validate(cmd *cobra.Command, args []string) error {
	calledAs := cmd.CalledAs()
	if calledAs == "attribute" && o.ID == "" {
		return fmt.Errorf(i18n.Translate("'id' flag is required."))
	}
	return nil
}

func (o *attributesOptions) Run(cmd *cobra.Command, args []string) error {
	if o.Entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+attributesEntitlements)
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	// invoke the operation
	calledAs := cmd.CalledAs()
	c := client.NewAttributeClient()
	var dataObj interface{}
	if calledAs == "attribute" {
		// deal with single attribute
		attr, err := c.GetAttribute(context.Background(), auth, o.ID)
		if err != nil {
			return err
		}
		dataObj = attr
	}

	if dataObj == nil {
		return fmt.Errorf("no data found.")
	}

	if len(o.OutputFile) == 0 {
		if o.OutputType == "json" {
			cmdutil.WriteAsJSON(cmd, dataObj, cmd.OutOrStdout())
		} else {
			cmdutil.WriteAsYAML(cmd, dataObj, cmd.OutOrStdout())
		}
	} else {
		of, err := os.Create(o.OutputFile)
		if err != nil {
			return err
		}

		defer of.Close()
		if o.OutputType == "json" {
			cmdutil.WriteAsJSON(cmd, dataObj, of)
		} else {
			cmdutil.WriteAsYAML(cmd, dataObj, of)
		}

		fullPath, err := filepath.Abs(o.OutputFile)
		if err != nil {
			fullPath = o.OutputFile
		}
		cmdutil.WriteString(cmd, fmt.Sprintf("File written: %s", fullPath))
	}

	return nil
}
