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
	LDAP struct {
		Host        string `yaml:"host"`
		Port        int    `yaml:"port"`
		Dn          string `yaml:"dn"`
		Password    string `yaml:"password"`
		UserSearch  string `yaml:"user_search"`
		GroupSearch string `yaml:"group_search"`
	} `yaml:"ldap"`
	DBDir string `yaml:"db_dir"`
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
