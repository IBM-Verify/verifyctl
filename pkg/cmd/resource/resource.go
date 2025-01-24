package resource

import (
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	ResourceTypePrefix = "IBMVerify"
)

type ResourceObjectList struct {
	Kind       string                  `json:"kind" yaml:"kind"`
	APIVersion string                  `json:"apiVersion" yaml:"apiVersion"`
	Metadata   *ResourceObjectMetadata `json:"metadata" yaml:"metadata"`
	Items      interface{}             `json:"items" yaml:"items"`
}

type ResourceObject struct {
	Kind       string                  `json:"kind" yaml:"kind"`
	APIVersion string                  `json:"apiVersion" yaml:"apiVersion"`
	Metadata   *ResourceObjectMetadata `json:"metadata" yaml:"metadata"`
	Data       interface{}             `json:"data" yaml:"data"`
}

type ResourceObjectMetadata struct {
	UID   string `json:"UID,omitempty" yaml:"UID,omitempty"`
	Name  string `json:"name,omitempty" yaml:"name,omitempty"`
	URI   string `json:"resourceUri,omitempty" yaml:"resourceUri,omitempty"`
	Limit int    `json:"limit,omitempty" yaml:"limit,omitempty"`
	Page  int    `json:"page,omitempty" yaml:"page,omitempty"`
	Total int    `json:"total,omitempty" yaml:"total,omitempty"`
	Count int    `json:"count,omitempty" yaml:"count,omitempty"`
}

func (r *ResourceObject) LoadFromFile(cmd *cobra.Command, file string, format string) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	var b []byte
	var err error

	if file == "-" {
		// read from stdin
		b, err = io.ReadAll(os.Stdin)
	} else {
		// get the contents of the file
		b, err = os.ReadFile(file)
	}

	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", file, err)
		return err
	}

	// determine format
	if format == "" {
		if strings.HasSuffix(file, ".json") {
			format = "json"
		} else {
			format = "yaml"
		}
	}

	// unmarshal to resource object
	if format == "json" {
		if err := json.Unmarshal(b, r); err != nil {
			vc.Logger.Errorf("unable to unmarshal the object; err=%v", err)
			return err
		}

	} else {
		if err := yaml.Unmarshal(b, r); err != nil {
			vc.Logger.Errorf("unable to unmarshal the object; err=%v", err)
			return err
		}
	}

	return nil
}
