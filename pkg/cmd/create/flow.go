package create

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/workflow"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"

	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

const (
	transformUsage         = "transform [options]"
	transformMessagePrefix = "TransformModel"
	transformEntitlements  = "Manage model transformations"
	transformResourceName  = "transform"
)

// ModelTransformRequest represents the request structure for model transformation
type ModelTransformRequest struct {
	ModelFile    io.Reader `json:"-"`
	SourceFormat string    `json:"sourceFormat" yaml:"sourceFormat"`
	TargetFormat string    `json:"targetFormat" yaml:"targetFormat"`
}

// ModelTransformClient represents the client for model transformation operations
type ModelTransformClient struct {
	Client *http.Client
}

var (
	transformShortDesc = cmdutil.TranslateShortDesc(transformMessagePrefix, "Additional options to transform a model.")

	transformLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(transformMessagePrefix, `
        Additional options to transform a model from one format to another.

Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:

    verifyctl create transform --boilerplate

You can identify the entitlement required by running:

    verifyctl create transform --entitlements`))

	transformExamples = templates.Examples(cmdutil.TranslateExamples(transformMessagePrefix, `
        # Create an empty transform resource. This can be piped into a file.
        verifyctl create transform --boilerplate

        # Transform a model using a file.
        verifyctl create transform -f=./model.onnx --source-format=onnx --target-format=tensorrt

        # Transform a model using a JSON configuration file.
        verifyctl create transform -c=./transform-config.json`))
)

type transformOptions struct {
	options

	config       *config.CLIConfig
	modelFile    string
	sourceFormat string
	targetFormat string
	configFile   string
	outputFile   string
}

func newTransformCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &transformOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   transformUsage,
		Short:                 transformShortDesc,
		Long:                  transformLongDesc,
		Example:               transformExamples,
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

func (o *transformOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, transformResourceName)
	cmd.Flags().StringVarP(&o.modelFile, "file", "f", "", "Path to the model file to transform.")
	cmd.Flags().StringVarP(&o.sourceFormat, "source-format", "s", "", "Source format of the model (e.g., onnx, tensorflow, pytorch).")
	cmd.Flags().StringVarP(&o.targetFormat, "target-format", "t", "", "Target format for the model (e.g., tensorrt, onnx, coreml).")
	cmd.Flags().StringVarP(&o.configFile, "config", "c", "", "Path to the JSON configuration file containing transform parameters.")
	cmd.Flags().StringVarP(&o.outputFile, "output", "o", "", "Path to save the transformed model (default: stdout).")
}

func (o *transformOptions) addCommonFlags(cmd *cobra.Command, resourceName string) {
	cmd.Flags().BoolVar(&o.boilerplate, "boilerplate", false, "Generate an empty "+resourceName+" resource.")
	cmd.Flags().BoolVar(&o.entitlements, "entitlements", false, "Display the entitlements required for this resource.")
}

func (o *transformOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *transformOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.configFile) > 0 {
		// If config file is provided, validate it exists
		if _, err := os.Stat(o.configFile); os.IsNotExist(err) {
			return errorsx.G11NError("Configuration file does not exist: %s", o.configFile)
		}
		return nil
	}

	if len(o.modelFile) == 0 {
		return errorsx.G11NError("The 'file' option is required if no config file is provided.")
	}

	if len(o.sourceFormat) == 0 {
		return errorsx.G11NError("The 'source-format' option is required if no config file is provided.")
	}

	if len(o.targetFormat) == 0 {
		return errorsx.G11NError("The 'target-format' option is required if no config file is provided.")
	}

	// Validate model file exists
	if _, err := os.Stat(o.modelFile); os.IsNotExist(err) {
		return errorsx.G11NError("Model file does not exist: %s", o.modelFile)
	}

	return nil
}

func (o *transformOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+transformEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "ModelTransform",
			APIVersion: "2.0",
			Data: &workflow.ModelTransformRequest{
				SourceFormat: "onnx",
				TargetFormat: "tensorrt",
			},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.transformModel(cmd)
}

func (o *transformOptions) transformModel(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	var result []byte
	var err error

	if len(o.configFile) > 0 {
		// Transform using config file
		result, err = o.transformModelWithConfig(cmd)
	} else {
		// Transform using direct parameters
		result, err = o.transformModelFromFile(ctx, o.modelFile, o.sourceFormat, o.targetFormat)
	}

	if err != nil {
		vc.Logger.Errorf("unable to transform model; err=%v", err)
		return err
	}

	// Output the result
	if len(o.outputFile) > 0 {
		// Save to file
		err = os.WriteFile(o.outputFile, result, 0644)
		if err != nil {
			vc.Logger.Errorf("unable to write output file; filename=%s, err=%v", o.outputFile, err)
			return errorsx.G11NError("unable to write output file; filename=%s, err=%v", o.outputFile, err)
		}
		cmdutil.WriteString(cmd, "Model transformed successfully and saved to: "+o.outputFile)
	} else {
		// Write to stdout
		_, err = cmd.OutOrStdout().Write(result)
		if err != nil {
			vc.Logger.Errorf("unable to write to stdout; err=%v", err)
			return errorsx.G11NError("unable to write to stdout; err=%v", err)
		}
	}

	return nil
}

func (o *transformOptions) transformModelFromFile(ctx context.Context, filePath, sourceFormat, targetFormat string) ([]byte, error) {

	// This is where you would call the actual ModelTransformClient

	client := workflow.NewModelTransformClient()
	return client.TransformModelFromFile(ctx, filePath, sourceFormat, targetFormat)
}

func (o *transformOptions) transformModelWithConfig(cmd *cobra.Command) ([]byte, error) {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// Read the config file
	configData, err := os.ReadFile(o.configFile)
	if err != nil {
		vc.Logger.Errorf("unable to read config file; filename=%s, err=%v", o.configFile, err)
		return nil, errorsx.G11NError("unable to read config file; filename=%s, err=%v", o.configFile, err)
	}

	// Parse the config
	var transformReq workflow.ModelTransformRequest
	if err := json.Unmarshal(configData, &transformReq); err != nil {
		vc.Logger.Errorf("unable to parse config file; err=%v", err)
		return nil, errorsx.G11NError("unable to parse config file; err=%v", err)
	}

	// Determine model file path - use from command line
	modelFilePath := o.modelFile
	if modelFilePath == "" {
		return nil, errorsx.G11NError("model file must be specified via --file option when using config file")
	}

	// This is where you would call the actual ModelTransformClient

	client := workflow.NewModelTransformClient()
	file, err := os.Open(modelFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	transformReq.ModelFile = file
	return client.TransformModelFromRequest(ctx, &transformReq)

}
