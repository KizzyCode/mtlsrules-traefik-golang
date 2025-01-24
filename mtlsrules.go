package mtlsrules_traefik_golang

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"slices"
)

// Plugin configuration
type Config struct {
	// The root CA certificate to validate against
	RootCert string `yaml:"rootCert" json:"rootCert"`
	// Status code to return in case the validation fails
	StatusCode int `yaml:"statusCode" json:"statusCode"`
	// Status text to return in case the validation fails
	StatusText string `yaml:"statusText" json:"statusText"`
	// Allowed common names
	CommonNames []string `yaml:"commonNames" json:"commonNames"`
	// Allowed serial numbers
	SerialNumbers []string `yaml:"serialNumbers" json:"serialNumbers"`
}

// The plugin object
type MtlsRules struct {
	// The plugin config
	config *Config
	// The next HTTP handler
	next http.Handler
	// The plugin name
	name string
	// Certificate pool cache
	certPool *x509.CertPool
}

// Creates a default config if the config is empty
func CreateConfig() *Config {
	return &Config{
		RootCert:      "",
		StatusCode:    403,
		StatusText:    "Forbidden",
		CommonNames:   nil,
		SerialNumbers: nil,
	}
}

// Initializes the plugin when Traefik starts
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Print some debugging info
	fmt.Printf("Initializing %q with config %+v\n", name, config)

	// Try to get cert from filesystem
	rootCert, err := os.ReadFile(config.RootCert)
	if err != nil {
		fmt.Printf("Cannot read root certificate at %s", config.RootCert)
		return nil, err
	}

	// Create certificate pool
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(rootCert)

	// Init plugin
	return &MtlsRules{
		config:   config,
		next:     next,
		name:     name,
		certPool: certPool,
	}, nil
}

// Plugin entrypoint for each HTTP request traefik reserves
func (plugin *MtlsRules) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	// Ensure the request is a TLS request
	if request.TLS == nil {
		fmt.Printf("Rejecting non-TLS request from %s", request.RemoteAddr)
		http.Error(response, plugin.config.StatusText, plugin.config.StatusCode)
		return
	}

	// Ensure the request has a peer certificate
	if len(request.TLS.PeerCertificates) == 0 {
		fmt.Printf("Rejecting non-mTLS request from %s", request.RemoteAddr)
		http.Error(response, plugin.config.StatusText, plugin.config.StatusCode)
		return
	}

	// Validate certificate validity
	peerCert := request.TLS.PeerCertificates[0]
	_, err := peerCert.Verify(x509.VerifyOptions{
		Roots:     plugin.certPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		fmt.Printf("Rejecting invalid mTLS certicate from %s (%s)", request.RemoteAddr, err)
		http.Error(response, plugin.config.StatusText, plugin.config.StatusCode)
		return
	}

	// Validate common name
	if plugin.config.CommonNames != nil {
		commonNameOk := slices.Contains(plugin.config.CommonNames, peerCert.Subject.CommonName)
		if !commonNameOk {
			fmt.Printf("Rejecting invalid mTLS certificate from %s (unknown common name: \"%s\")", request.RemoteAddr, peerCert.Subject.CommonName)
			http.Error(response, plugin.config.StatusText, plugin.config.StatusCode)
			return
		}
	}

	// Validate serial numbers
	if plugin.config.SerialNumbers != nil {
		serialNumberOk := slices.Contains(plugin.config.SerialNumbers, peerCert.Subject.SerialNumber)
		if !serialNumberOk {
			fmt.Printf("Rejecting invalid mTLS certificate from %s (unknown serial number: \"%s\")", request.RemoteAddr, peerCert.Subject.SerialNumber)
			http.Error(response, plugin.config.StatusText, plugin.config.StatusCode)
			return
		}
	}

	// Request seems to be valid
	plugin.next.ServeHTTP(response, request)
}
