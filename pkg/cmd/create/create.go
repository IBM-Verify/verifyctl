package create

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

const (
	usage         = "create -f=FILENAME [options]"
	messagePrefix = "Create"
)

var (
	shortDesc = cmdutil.TranslateShortDesc(messagePrefix, "Create a Verify resource.")

	longDesc = templates.LongDesc(cmdutil.TranslateLongDesc(messagePrefix, `
		Create a Verify resource from a file.

JSON or YAML formats are accepted and determined based on the file extension.

An empty resource file can be generated using:

  verifyctl create [resource-type] --boilerplate
		
Resources managed on Verify require specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl create [resource-type] --entitlements

Certain resources may offer additional options and can be determined using:

  verifyctl create [resource-type] -h`))

	examples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Create an application
		verifyctl create -f=./app-1098012.json`))

	// # Create and get an attribute
	// verifyctl create -f=./attribute.yml -o=yaml

	entitlementsMessage = i18n.Translate("Choose any of the following entitlements to configure your application or API client:\n")
)

type options struct {
	entitlements bool
	boilerplate  bool
	file         string
	//output       string

	config *config.CLIConfig
}

func NewCommand(config *config.CLIConfig, streams io.ReadWriter, groupID string) *cobra.Command {
	o := &options{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   usage,
		Short:                 shortDesc,
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

	// add sub commands
	cmd.AddCommand(newAttributeCommand(config, streams))
	cmd.AddCommand(newUserCommand(config, streams))
	cmd.AddCommand(newGroupCommand(config, streams))
	cmd.AddCommand(newAccessPolicyCommand(config, streams))
	cmd.AddCommand(newIdentitySourceCommand(config, streams))
	cmd.AddCommand(newAPIClientCommand(config, streams))
	cmd.AddCommand(newApplicationCommand(config, streams))
	cmd.AddCommand(newIdentityAgentCommand(config, streams))
	cmd.AddCommand(newPasswordPolicyCommand(config, streams))
	cmd.AddCommand(newPersonalCertCommand(config, streams))
	cmd.AddCommand(newSignerCertCommand(config, streams))

	return cmd
}

func (o *options) addCommonFlags(cmd *cobra.Command, resourceName string) {
	cmd.Flags().BoolVar(&o.entitlements, "entitlements", o.entitlements, i18n.Translate("List the entitlements that can be configured to grant access to the resource. This is useful to know what to configure on the application or API client used to generate the login token. When this flag is used, the others are ignored."))
	cmd.Flags().BoolVar(&o.boilerplate, "boilerplate", o.boilerplate, i18n.TranslateWithArgs("Generate an empty %s file. This will be in YAML format.", resourceName))
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file that contains the input data. JSON and YAML formats are supported and the files are expected to be named with the appropriate extension: json, yml or yaml."))
	//cmd.Flags().StringVarP(&o.output, "output", "o", "", i18n.Translate("Fetches the newly created resource in the indicated format. The values supported are 'json' , 'yaml' and 'raw'. Default: 'yaml'."))
}

func (o *options) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *options) Validate(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	if len(o.file) == 0 {
		return errorsx.G11NError("'file' option is required")
	}

	// read the file
	resourceObject, err := o.readFile(cmd)
	if err != nil {
		return err
	}

	if len(resourceObject.Kind) == 0 {
		return errorsx.G11NError("No 'kind' defined. Resource type cannot be identified.")
	}

	_, err = o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	switch resourceObject.Kind {
	case resource.ResourceTypePrefix + "Attribute":
		options := &attributeOptions{}
		err = options.createAttributeFromDataMap(cmd, resourceObject.Data.(map[string]interface{}))

	case resource.ResourceTypePrefix + "User":
		options := &userOptions{}
		err = options.createUserFromDataMap(cmd, resourceObject.Data.(map[string]interface{}))

	case resource.ResourceTypePrefix + "Group":
		options := &groupOptions{}
		err = options.createGroupFromDataMap(cmd, resourceObject.Data.(map[string]interface{}))

	case resource.ResourceTypePrefix + "AccessPolicy":
		options := &accessPolicyOptions{}
		err = options.createAccessPolicyFromDataMap(cmd, resourceObject.Data.(map[string]interface{}))

	case resource.ResourceTypePrefix + "IdentitySource":
		options := &identitySourceOptions{}
		err = options.createIdentitySourceFromDataMap(cmd, resourceObject.Data.(map[string]interface{}))

	case resource.ResourceTypePrefix + "APIClient":
		options := &apiClientOptions{}
		err = options.createAPIClientFromDataMap(cmd, resourceObject.Data.(map[string]interface{}))

	case resource.ResourceTypePrefix + "Applications":
		options := &applicationOptions{}
		err = options.createApplicationFromDataMap(cmd, resourceObject.Data.(map[string]interface{}))

	case resource.ResourceTypePrefix + "IdentityAgent":
		options := &identityAgentOptions{}
		err = options.createIdentityAgentFromDataMap(cmd, resourceObject.Data.(map[string]interface{}))

	case resource.ResourceTypePrefix + "PasswordPolicy":
		options := &passwordPolicyOptions{}
		err = options.createPasswordPolicyFromDataMap(cmd, resourceObject.Data.(map[string]interface{}))

	case resource.ResourceTypePrefix + "PersonalCert":
		options := &personalCertOptions{}
		err = options.createPersonalCertFromDataMap(cmd, resourceObject.Data.(map[string]interface{}))

	case resource.ResourceTypePrefix + "SignerCert":
		options := &signerCertOptions{}
		err = options.createSignerCertFromDataMap(cmd, resourceObject.Data.(map[string]interface{}))

	}

	return err
}

func (o *options) readFile(cmd *cobra.Command) (*resource.ResourceObject, error) {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	resourceObject := &resource.ResourceObject{}
	if err := resourceObject.LoadFromFile(cmd, o.file, ""); err != nil {
		vc.Logger.Errorf("unable to read file contents into resource object; err=%v", err)
		return nil, err
	}

	return resourceObject, nil
}
