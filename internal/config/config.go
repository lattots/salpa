package config

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

func ReadConfiguration(filename string) (SystemConfiguration, error) {
	if _, err := os.Stat(filename); err != nil {
		return SystemConfiguration{}, fmt.Errorf("configuration file doesn't exist in %s", filename)
	}
	f, err := os.Open(filename)
	if err != nil {
		return SystemConfiguration{}, err
	}
	defer f.Close()

	fileContent, err := io.ReadAll(f)
	if err != nil {
		return SystemConfiguration{}, err
	}

	var conf SystemConfiguration
	if err := yaml.Unmarshal(fileContent, &conf); err != nil {
		return SystemConfiguration{}, fmt.Errorf("error parsing configuration file: %w", err)
	}

	return conf, nil
}

type SystemConfiguration struct {
	Providers map[string]ProviderConfig `yaml:"providers"`
	Store     StoreConfig               `yaml:"store"`
	Service   ServiceConfiguration      `yaml:"service"`
}

type ProviderConfig struct {
	Active               bool              `yaml:"active"`
	EnvironmentVariables map[string]string `yaml:"env"`
}

type StoreConfig struct {
	Driver           string `yaml:"driver"`
	ConnectionString string `yaml:"connectionString"`
}

type ServiceConfiguration struct {
	PrivateKeyFilename string `yaml:"privateKeyFilename"`

	Port int `yaml:"port"`

	ServiceDomain string `yaml:"serviceDomain"`
	AppDomain     string `yaml:"appDomain"`
}
