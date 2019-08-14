package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// Config deepin tracker default configurations
type Config struct {
	Server struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"server"`
	DB struct {
		CVEFile     string `yaml:"cve_file"`
		PackageFile string `yaml:"package_file"`
	} `yaml:"db"`
	DebianTracker struct {
		BaseURL string `yaml:"base_url"`
		HomeURL string `yaml:"home_url"`
	} `yaml:"debian_tracker"`
	PackagesFile string `yaml:"packages_file"`
	AccessToken  string `yaml:"access_token"`
}

const (
	defaultConfigFile = "/etc/deepin-cve-tracker/config.yaml"
)

var (
	_config *Config
)

func GetConfig(filename string) *Config {
	if _config == nil {
		if len(filename) == 0 {
			filename = defaultConfigFile
		}
		conf, err := newConfig(filename)
		if err != nil {
			panic(err)
		}
		_config = conf
	}
	return _config
}

func newConfig(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var conf Config
	err = yaml.Unmarshal(content, &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
