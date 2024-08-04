package get

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/i18n"
	"github.com/ibm-security-verify/verifyctl/pkg/module/branding"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	themesUsage         = `themes [flags]`
	themesMessagePrefix = "GetThemes"
	themesEntitlements  = "manageTemplates (Manage templates and themes) or readTemplates (Read templates and themes)"
)

var (
	themesLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(themesMessagePrefix, `
		Get themes.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl get themes --entitlements`))

	themesExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# List themes
		verifyctl get themes --outfile=./themes.yaml --page=1 --limit=100
		
		# Download a single theme as a zip file
		verifyctl get theme --id=mythemeid --outfile=./theme.zip
		
		# Download a single theme and uncompress it to a directory
		verifyctl get theme --id=mythemeid --unpack --outdir=./mythemeid`))
)

type themesOptions struct {
	options
	page            int
	limit           int
	count           int
	id              string
	path            string
	outputDirectory string
	unpack          bool
	customizedOnly  bool

	config *config.CLIConfig
}

func NewThemesCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &themesOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   themesUsage,
		Short:                 cmdutil.TranslateShortDesc(themesMessagePrefix, "Get themes."),
		Long:                  themesLongDesc,
		Example:               themesExamples,
		Aliases:               []string{"theme"},
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

func (o *themesOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().IntVar(&o.count, "count", 0, i18n.Translate("Define the total number of results that are returned from the data store. The maximum allowed value is 1000."))
	cmd.Flags().IntVar(&o.limit, "limit", 0, i18n.Translate("Define the total number of results that are returned per page. The maximum allowed value is 1000."))
	cmd.Flags().IntVar(&o.page, "page", 0, i18n.Translate("Identify the requested page, or the offset."))
	cmd.Flags().StringVar(&o.id, "id", "", i18n.Translate("Identifier of the theme."))
	cmd.Flags().StringVar(&o.path, "path", "", i18n.Translate("Template file path, including the locale if relevant. This is only meant to be used when downloading a single file."))
	cmd.Flags().StringVar(&o.outputDirectory, "outdir", "", i18n.Translate("Path to the directory where the theme will be unpacked, if requested. This is paired with 'unpack' flag."))
	cmd.Flags().BoolVar(&o.unpack, "unpack", false, i18n.Translate("Uncompress the downloaded zip. This is only used for single theme download commands."))
	cmd.Flags().BoolVar(&o.customizedOnly, "customizedOnly", false, i18n.Translate("Use the flag if you only want customized template files. This is only used for single theme download commands."))
}

func (o *themesOptions) Complete(cmd *cobra.Command, args []string) error {
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

func (o *themesOptions) Validate(cmd *cobra.Command, args []string) error {
	calledAs := cmd.CalledAs()
	if calledAs == "theme" {
		if o.id == "" {
			return fmt.Errorf(i18n.Translate("'id' flag is required."))
		}

		if len(o.outputDirectory) == 0 && len(o.OutputFile) == 0 {
			return fmt.Errorf(i18n.Translate("Either 'outdir' or 'outfile' flag is required when downloading a single theme."))
		}

		if len(o.outputDirectory) == 0 && o.unpack {
			return fmt.Errorf(i18n.Translate("'outdir' flag is required when 'unpack' flag is used."))
		}
	}
	return nil
}

func (o *themesOptions) Run(cmd *cobra.Command, args []string) error {
	if o.Entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+themesEntitlements)
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	// invoke the operation
	calledAs := cmd.CalledAs()
	c := branding.NewThemeClient()

	if calledAs == "theme" {
		return o.handleSingleThemeCommand(cmd, auth, args)
	}

	// deal with themes
	themes, err := c.ListThemes(cmd.Context(), auth, o.count, o.page, o.limit)
	if err != nil {
		return err
	}

	if len(o.OutputFile) == 0 {
		if o.OutputType == "json" {
			cmdutil.WriteAsJSON(cmd, themes.Themes, cmd.OutOrStdout())
		} else {
			cmdutil.WriteAsYAML(cmd, themes.Themes, cmd.OutOrStdout())
		}
	} else {
		of, err := os.Create(o.OutputFile)
		if err != nil {
			return err
		}

		defer of.Close()
		if o.OutputType == "json" {
			cmdutil.WriteAsJSON(cmd, themes.Themes, of)
		} else {
			cmdutil.WriteAsYAML(cmd, themes.Themes, of)
		}

		fullPath, err := filepath.Abs(o.OutputFile)
		if err != nil {
			fullPath = o.OutputFile
		}
		cmdutil.WriteString(cmd, fmt.Sprintf("File written: %s", fullPath))
	}

	return nil
}

func (o *themesOptions) handleSingleThemeCommand(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {
	c := branding.NewThemeClient()
	var b []byte
	var err error
	if len(o.path) > 0 {
		// get a single file
		b, err = c.GetFile(cmd.Context(), auth, o.id, o.path)
	} else {
		b, err = c.GetTheme(cmd.Context(), auth, o.id, o.customizedOnly)
	}

	if err != nil {
		return err
	}

	if len(o.path) == 0 && o.unpack {
		return cmdutil.UnpackZipToDirectory(cmd, b, o.outputDirectory)
	}

	// write the file
	of, err := os.Create(o.OutputFile)
	if err != nil {
		return err
	}

	defer of.Close()
	cmdutil.WriteAsBinary(cmd, b, of)

	fullPath, err := filepath.Abs(o.OutputFile)
	if err != nil {
		fullPath = o.OutputFile
	}
	cmdutil.WriteString(cmd, fmt.Sprintf("File written: %s", fullPath))
	return nil
}
