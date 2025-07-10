package manifest

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/stackrox/rox/pkg/utils"
	"gopkg.in/yaml.v3"
)

const (
	localStackroxImage = "localhost:5001/stackrox/stackrox:latest"
	localDbImage       = "localhost:5001/stackrox/db:latest"
)

type Config struct {
	Action               string `yaml:"action"`
	ApplyNetworkPolicies bool   `yaml:"applyNetworkPolicies"`
	CRS                  CRS    `yaml:"crs"`
	CertPath             string `yaml:"certPath"`
	DevMode              bool   `yaml:"devMode"`
	Images               Images `yaml:"images"`
	Namespace            string `yaml:"namespace"`
	ScannerV4            bool   `yaml:"scannerV4"`
}

type CRS struct {
	PortForward bool `yaml:"portForward"`
}

type Images struct {
	AdmissionControl string `yaml:"admissionControl"`
	Sensor           string `yaml:"sensor"`
	Collector        string `yaml:"collector"`
	ConfigController string `yaml:"configController"`
	Central          string `yaml:"central"`
	CentralDB        string `yaml:"centralDb"`
	Scanner          string `yaml:"scanner"`
	ScannerDB        string `yaml:"scannerDb"`
	ScannerV4        string `yaml:"scannerv4"`
	ScannerV4DB      string `yaml:"scannerv4Db"`
	VSOCKListener    string `yaml:"vsockListener"`
}

var DefaultConfig Config = Config{
	Namespace:            "stackrox",
	ScannerV4:            false,
	DevMode:              false,
	ApplyNetworkPolicies: false,
	CertPath:             "./certs",
	Images: Images{
		AdmissionControl: localStackroxImage,
		Sensor:           localStackroxImage,
		Collector:        localStackroxImage,
		ConfigController: localStackroxImage,
		Central:          localStackroxImage,
		Scanner:          localStackroxImage,
		ScannerV4:        localStackroxImage,
		VSOCKListener:    localStackroxImage,
		CentralDB:        localDbImage,
		ScannerDB:        localDbImage,
		ScannerV4DB:      localDbImage,
	},
}

func ReadConfig(filename string) (*Config, error) {
	if filename == "" {
		cfg := DefaultConfig
		return &cfg, nil
	}
	r, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer utils.IgnoreError(r.Close)
	return load(r)
}

func load(r io.Reader) (*Config, error) {
	yd := yaml.NewDecoder(r)
	yd.KnownFields(true)
	cfg := DefaultConfig
	if err := yd.Decode(&cfg); err != nil {
		msg := strings.TrimPrefix(err.Error(), `yaml: `)
		return nil, fmt.Errorf("malformed yaml: %v", msg)
	}
	return &cfg, nil
}
