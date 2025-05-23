package set

import (
	"io"
	"os"
	"path/filepath"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/branding"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	themesUsage         = `theme [flags]`
	themesMessagePrefix = "SetTheme"
	themesEntitlements  = "manageTemplates (Manage templates and themes)"
	themeResourceName   = "theme"
)

var (
	themesLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(themesMessagePrefix, `
		Update a theme or theme files.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl set theme --entitlements`))

	themesExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Update theme using a zip file
		verifyctl set theme --id=mythemeid --file=./mytheme.zip

		# Update theme by pointing at a directory with the theme directory structure, starting
		# with 'templates' directory
		verifyctl set theme --id=mythemeid --dir=./mytheme
		
		# Upload a theme template file
		verifyctl set theme --id=mythemeid --file=./mylogo.png --path=common/logo/default/logo.png`))
)

type themesOptions struct {
	options
	directory string
	path      string

	config *config.CLIConfig
}

func newThemesCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &themesOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   themesUsage,
		Short:                 cmdutil.TranslateShortDesc(themesMessagePrefix, "Update a theme or theme files."),
		Long:                  themesLongDesc,
		Example:               themesExamples,
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
	o.addCommonFlags(cmd, themeResourceName)
	cmd.Flags().StringVarP(&o.path, "template", "T", "", i18n.Translate("Template file path, including the locale. This is only meant to be used when updating a single file. The 'format' flag is assumed to be 'raw' in this case."))
	cmd.Flags().StringVar(&o.directory, "dir", "", i18n.Translate("Path to the directory where the theme is unpacked. The contents of the directory will be compressed and uploaded as the theme."))
}

func (o *themesOptions) Complete(cmd *cobra.Command, args []string) error {
	o.entitlements = cmd.Flag("entitlements").Changed
	o.file = cmd.Flag("file").Value.String()
	return nil
}

func (o *themesOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	if o.id == "" {
		return errorsx.G11NError("'id' flag is required.")
	}

	if len(o.path) > 0 && len(o.file) == 0 {
		return errorsx.G11NError("'%s' flag is required.", "file")
	}

	if len(o.directory) == 0 && len(o.file) == 0 {
		return errorsx.G11NError("Either 'dir' or 'file' flag is required.")
	}

	return nil
}

func (o *themesOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+themesEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	// invoke the operation
	return o.handleSingleThemeCommand(cmd, args)
}

func (o *themesOptions) handleSingleThemeCommand(cmd *cobra.Command, _ []string) error {
	c := branding.NewThemeClient()
	if len(o.path) > 0 {
		// get the contents of the file
		b, err := os.ReadFile(o.file)
		if err != nil {
			return err
		}

		// update a single file
		return c.UpdateFile(cmd.Context(), o.id, o.path, b)
	}

	var zipBuffer []byte
	var err error
	if len(o.directory) > 0 {
		sourceDirectory := ""
		if sourceDirectory, err = filepath.Abs(o.directory); err != nil {
			sourceDirectory = o.directory
		}

		zipBuffer, err = cmdutil.CreateZipFromDirectory(cmd, sourceDirectory)
	} else {
		zipBuffer, err = os.ReadFile(o.file)
	}

	if err != nil {
		return err
	}

	return c.UpdateTheme(cmd.Context(), o.id, zipBuffer, nil)
}
