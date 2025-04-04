package get

import (
	"encoding/base64"
	"io"

	"github.com/ibm-security-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/i18n"
	"github.com/ibm-security-verify/verifyctl/pkg/module"
	"github.com/ibm-security-verify/verifyctl/pkg/module/branding"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	themesUsage         = `themes [flags]`
	themesMessagePrefix = "GetThemes"
	themesEntitlements  = "manageTemplates (Manage templates and themes) or readTemplates (Read templates and themes)"
	themeResourceName   = "theme"
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
	o.addCommonFlags(cmd, themeResourceName)
	o.addPaginationFlags(cmd, themeResourceName)

	o.addIdFlag(cmd, attributeResourceName)
	cmd.Flags().BoolVar(&o.customizedOnly, "customizedOnly", false, i18n.Translate("Use the flag if you only want customized template files. This is only used for single theme downloads."))
	cmd.Flags().BoolVar(&o.unpack, "unpack", false, i18n.Translate("Uncompress the downloaded zip. This is only used for single theme download commands."))
	cmd.Flags().StringVar(&o.outputDirectory, "dir", "", i18n.Translate("Path to the directory where the theme will be unpacked, if requested. This is paired with 'unpack' flag."))
	cmd.Flags().StringVarP(&o.path, "template", "T", "", i18n.Translate("Template path, including the locale if relevant. This is only meant to be used when downloading a single file. Example: 'authentication/oidc/consent/default/user_consent.html'."))
}

func (o *themesOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *themesOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "theme" {
		if o.id == "" {
			return module.MakeSimpleError(i18n.Translate("'id' flag is required."))
		}

		if len(o.outputDirectory) == 0 && o.unpack {
			return module.MakeSimpleError(i18n.Translate("'dir' flag is required when 'unpack' flag is used."))
		}
	}
	return nil
}

func (o *themesOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+themesEntitlements)
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "theme" || len(o.id) > 0 {
		return o.handleSingleThemeCommand(cmd, auth, args)
	}

	// deal with themes
	c := branding.NewThemeClient()
	themes, uri, err := c.ListThemes(cmd.Context(), auth, 0, o.page, o.limit)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, themes, cmd.OutOrStdout())
		return nil
	}

	items := []*resource.ResourceObject{}
	for _, theme := range themes.Themes {
		items = append(items, &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "Theme",
			APIVersion: "1.0",
			Metadata: &resource.ResourceObjectMetadata{
				UID:  theme.ThemeID,
				Name: theme.Name,
			},
			Data: theme,
		})
	}

	resourceObj := &resource.ResourceObjectList{
		Kind:       resource.ResourceTypePrefix + "List",
		APIVersion: "1.0",
		Metadata: &resource.ResourceObjectMetadata{
			URI:   uri,
			Limit: themes.Limit,
			Count: themes.Count,
			Total: themes.Total,
			Page:  themes.Page,
		},
		Items: items,
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}

	return nil
}

func (o *themesOptions) handleSingleThemeCommand(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {
	c := branding.NewThemeClient()
	var b []byte
	var err error
	uri := ""
	uid := o.id
	resourceName := "Theme"
	if len(o.path) > 0 {
		// get a single file
		if b, uri, err = c.GetFile(cmd.Context(), auth, o.id, o.path); err != nil {
			return err
		}
		resourceName = "ThemeFile"
	} else {
		if b, uri, err = c.GetTheme(cmd.Context(), auth, o.id, o.customizedOnly); err != nil {
			return err
		}
	}

	if len(o.path) == 0 && o.unpack {
		return cmdutil.UnpackZipToDirectory(cmd, b, o.outputDirectory)
	}

	if o.output == "raw" {
		cmdutil.WriteAsBinary(cmd, b, cmd.OutOrStdout())
		return nil
	}

	obj := &resource.ResourceObject{
		Kind:       string(resource.ResourceTypePrefix) + resourceName,
		APIVersion: "1.0",
		Metadata: &resource.ResourceObjectMetadata{
			UID: uid,
			URI: uri,
		},
		Data: base64.StdEncoding.EncodeToString(b),
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, obj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, obj, cmd.OutOrStdout())
	}

	return nil
}
