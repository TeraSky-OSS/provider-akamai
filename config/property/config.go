package property

import (
	"github.com/crossplane/upjet/pkg/config"
)

// Configure configures the property category resources.
func Configure(p *config.Provider) {
	p.AddResourceConfigurator("akamai_property", func(r *config.Resource) {
		r.ShortGroup = "property"
		r.Kind = "Property"
	})
	p.AddResourceConfigurator("akamai_property_activation", func(r *config.Resource) {
		r.ShortGroup = "property"
		r.Kind = "Activation"
	})
	p.AddResourceConfigurator("akamai_property_bootstrap", func(r *config.Resource) {
		r.ShortGroup = "property"
		r.Kind = "Bootstrap"
	})
	p.AddResourceConfigurator("akamai_property_include", func(r *config.Resource) {
		r.ShortGroup = "property"
		r.Kind = "Include"
	})
	p.AddResourceConfigurator("akamai_property_include_activation", func(r *config.Resource) {
		r.ShortGroup = "property"
		r.Kind = "IncludeActivation"
	})
}
