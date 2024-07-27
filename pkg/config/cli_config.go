package config

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	apiVersion  = "1.0"
	kind        = "Config"
	defaultDir  = ".verify"
	fileName    = "config"
	defaultPerm = os.ModePerm
)

type CLIConfig struct {
	APIVersion string        `yaml:"apiVersion"`
	Kind       string        `yaml:"kind"`
	Auth       []*AuthConfig `yaml:"auth"`
}

type AuthConfig struct {
	Tenant string `yaml:"tenant"`
	Token  string `yaml:"token"`
	User   bool   `yaml:"isUser"`
}

func NewCLIConfig() *CLIConfig {
	return &CLIConfig{
		APIVersion: apiVersion,
		Kind:       kind,
		Auth:       []*AuthConfig{},
	}
}

func (o *CLIConfig) AddAuth(config *AuthConfig) {
	// check if it already exists and replace if so
	for _, c := range o.Auth {
		if c.Tenant == config.Tenant {
			// replace
			c.Merge(config)
			return
		}
	}

	// add it to the auth list
	o.Auth = append(o.Auth, config)
}

func (o *CLIConfig) LoadFromFile() (*CLIConfig, error) {
	configDir, err := o.createOrGetDir()
	if err != nil {
		return o, err
	}

	configFile := filepath.Join(configDir, fileName)
	if _, err := os.Stat(configFile); errors.Is(err, os.ErrNotExist) {
		// do nothing. the file will get created when something needs to be added.
		return o, nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return o, err
	}

	if err = yaml.Unmarshal(data, o); err != nil {
		return o, err
	}

	return o, nil
}

func (o *CLIConfig) PersistFile() (*CLIConfig, error) {
	data, err := yaml.Marshal(o)
	if err != nil {
		return o, err
	}

	configDir, err := o.createOrGetDir()
	if err != nil {
		return o, err
	}

	configFile := filepath.Join(configDir, fileName)
	if err = os.WriteFile(configFile, data, defaultPerm); err != nil {
		return o, err
	}

	return o, nil
}

func (o *CLIConfig) createOrGetDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	configDir := os.Getenv("VERIFY_CONFIG")
	if configDir == "" {
		configDir = filepath.Join(homeDir, defaultDir)
	}

	if err := os.MkdirAll(configDir, defaultPerm); err != nil {
		return "", err
	}

	return configDir, nil
}

func (o *AuthConfig) Merge(c *AuthConfig) {
	o.Tenant = c.Tenant
	o.Token = c.Token
	o.User = c.User
}
