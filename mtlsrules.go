package mtlsrules_traefik_golang

import (
	"context"
	"fmt"
	"slices"
	"net/http"
	"encoding/asn1"
	"regexp"
	"strings"
)

var commonNameOID = asn1.ObjectIdentifier{2, 5, 4, 3}
var organizationOID = asn1.ObjectIdentifier{2, 5, 4, 10}
var organizationUnitOID = asn1.ObjectIdentifier{2, 5, 4, 11}
var initialsOID = asn1.ObjectIdentifier{2, 5, 4, 43}
var pseudonymOID = asn1.ObjectIdentifier{2, 5, 4, 65}
var UIDOid = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}

// Plugin configuration
type Config struct {
	// Status code to return in case the validation fails
	StatusCode int `yaml:"statusCode" json:"statusCode"`
	// Status text to return in case the validation fails
	StatusText string `yaml:"statusText" json:"statusText"`
	// X509 values rules
	// Note: Keep the config name short to avoid overly long lines
	O string `yaml:"o" json:"o"`
	OU string `yaml:"ou" json:"ou"`
	CN string `yaml:"cn" json:"cn"`
	INITIALS string `yaml:"initials" json:"initials"`
	PSEUDONYM string `yaml:"pseudonym" json:"pseudonym"`
	UID string `yaml:"uid" json:"uid"`
	EMAIL string `yaml:"email" json:"email"`
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
		O: "",
		OU: "",
		CN: "",
		INITIALS: "",
		UID: "",
		PSEUDONYM: "",
		EMAIL: "",
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

	var	x509Organization []string
	var	x509OrganizationUnit []string
	var x509ComonName []string
	var x509Initials []string
	var x509Pseudonym []string
	var x509UID []string
	var x509Email []string

	// Retrive certificate informations
	x509Email = request.TLS.PeerCertificates[0].EmailAddresses
	for _, atv := range request.TLS.PeerCertificates[0].Subject.Names {
		if atv.Type.Equal(organizationOID) {
			if d, ok := atv.Value.(string); ok {
				x509Organization = append(x509Organization, d)
			}
		}
		if atv.Type.Equal(organizationUnitOID) {
			if d, ok := atv.Value.(string); ok {
				x509OrganizationUnit = append(x509OrganizationUnit, d)
			}
		}
		if atv.Type.Equal(commonNameOID) {
			if d, ok := atv.Value.(string); ok {
				x509ComonName = append(x509ComonName, d)
			}
		}
		if atv.Type.Equal(initialsOID) {
			if d, ok := atv.Value.(string); ok {
				x509Initials = append(x509Initials, d)
			}
		}
		if atv.Type.Equal(pseudonymOID) {
			if d, ok := atv.Value.(string); ok {
				x509Pseudonym = append(x509Pseudonym, d)
			}
		}
		if atv.Type.Equal(UIDOid) {
			if d, ok := atv.Value.(string); ok {
				x509UID = append(x509UID, d)
			}
		}
	}
	

	var checks []bool
	validate(plugin.config.O, x509Organization, &checks)
	validate(plugin.config.OU, x509OrganizationUnit, &checks)
	validate(plugin.config.CN, x509ComonName, &checks)
	validate(plugin.config.INITIALS, x509Initials, &checks)
	validate(plugin.config.UID, x509UID, &checks)
	validate(plugin.config.PSEUDONYM, x509Pseudonym, &checks)
	validate(plugin.config.EMAIL, x509Email, &checks)

	// We finaly check that array only contains true values
	if allGood(&checks) {
		plugin.next.ServeHTTP(response, request)
		return
	}

	// Validation chain did not succeed
	fmt.Printf("Rejecting invalid mTLS certificate from %s (CN: \"%s\")",
		request.RemoteAddr, x509ComonName[0])
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

func validate(cnfValue string, x509Value []string, checks *[]bool) {
		// We do have a config value
	    if cnfValue != "" {
			*checks = append(*checks, slices.Contains(x509Value, cnfValue))
		}
}

func allGood(values *[]bool) bool {
	if len(*values) == 0 {
		return false
	}
	
	for _, i := range *values {
        if !i {
            return false
        }
    }
    return true
}
