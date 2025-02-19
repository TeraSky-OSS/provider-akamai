package cloudwrapper

import (
	"github.com/crossplane/upjet/pkg/config"
)

// Configure configures the cloudwrapper category resources.
func Configure(p *config.Provider) {
	p.AddResourceConfigurator("akamai_cloudwrapper_activation", func(r *config.Resource) {
		r.ShortGroup = "cloudwrapper"
		r.Kind = "Activation"
	})
	p.AddResourceConfigurator("akamai_cloudwrapper_configuration", func(r *config.Resource) {
		r.ShortGroup = "cloudwrapper"
		r.Kind = "Configuration"
	})
}
