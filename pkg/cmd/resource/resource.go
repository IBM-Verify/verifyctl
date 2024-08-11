package resource

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
