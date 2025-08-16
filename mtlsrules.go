package mtlsrules_traefik_golang

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Plugin configuration
type Config struct {
	// Status code to return in case the validation fails
	StatusCode int `yaml:"statusCode" json:"statusCode"`
	// Status text to return in case the validation fails
	StatusText string `yaml:"statusText" json:"statusText"`
	// Common name rules
	// Note: Keep the config name short to avoid overly long lines
	CN string `yaml:"cn" json:"cn"`
}

// The plugin object
type MtlsRules struct {
	// The plugin config
	config *Config
	// The next HTTP handler
	next http.Handler
	// The plugin name
	name string
}

// Creates a default config if the config is empty
func CreateConfig() *Config {
	return &Config{
		StatusCode: 403,
		StatusText: "Forbidden (mTLS)",
		CN:         "",
	}
}

// Initializes the plugin when Traefik starts
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Print some debugging info
	fmt.Printf("Initializing %q with config %+v\n", name, config)

	// Init plugin
	return &MtlsRules{
		config: config,
		next:   next,
		name:   name,
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

	// We explicitly take cert[0] here, as the chain should already have been verified, so we are only interested in the
	// 	identity of the individual leaf cert
	peerCert := request.TLS.PeerCertificates[0]
	cnRuleKind, cnRule := parseRule(plugin.config.CN)

	// Validate regex rule if given
	if cnRuleKind == "Regex" {
		commonNameOk, err := regexp.MatchString(cnRule, peerCert.Subject.CommonName)
		if err != nil {
			fmt.Printf("Failed to match CN regex for %s (%s)", request.RemoteAddr, err)
			http.Error(response, plugin.config.StatusText, plugin.config.StatusCode)
			return
		}
		if commonNameOk {
			plugin.next.ServeHTTP(response, request)
			return
		}
	}

	// Validation chain did not succeed
	fmt.Printf("Rejecting invalid mTLS certificate from %s (CN: \"%s\")",
		request.RemoteAddr, peerCert.Subject.CommonName)
	http.Error(response, plugin.config.StatusText, plugin.config.StatusCode)
}

// El-cheapo-parser to parse a rule of the format: Kind(`rule`)
func parseRule(rule string) (string, string) {
	// We trim the string due to multiline configs
	rule = strings.TrimSpace(rule)

	// Split-off kind
	kind, remainder, found := strings.Cut(rule, "(`")
	if !found {
		return "", ""
	}

	// Split-off value
	value, found := strings.CutSuffix(remainder, "`)")
	if !found {
		return "", ""
	}

	// Return kind and value
	return kind, value
}
