package gtm

import (
	"github.com/crossplane/upjet/pkg/config"
)

// Configure configures the GTM category resources.
func Configure(p *config.Provider) {
	p.AddResourceConfigurator("akamai_gtm_asmap", func(r *config.Resource) {
		r.ShortGroup = "gtm"
		r.Kind = "ASMap"
	})
	p.AddResourceConfigurator("akamai_gtm_cidrmap", func(r *config.Resource) {
		r.ShortGroup = "gtm"
		r.Kind = "CIDRMap"
	})
	p.AddResourceConfigurator("akamai_gtm_datacenter", func(r *config.Resource) {
		r.ShortGroup = "gtm"
		r.Kind = "Datacenter"
	})
	p.AddResourceConfigurator("akamai_gtm_domain", func(r *config.Resource) {
		r.ShortGroup = "gtm"
		r.Kind = "Domain"
	})
	p.AddResourceConfigurator("akamai_gtm_geomap", func(r *config.Resource) {
		r.ShortGroup = "gtm"
		r.Kind = "GeoMap"
	})
	p.AddResourceConfigurator("akamai_gtm_property", func(r *config.Resource) {
		r.ShortGroup = "gtm"
		r.Kind = "Property"
	})
	p.AddResourceConfigurator("akamai_gtm_resource", func(r *config.Resource) {
		r.ShortGroup = "gtm"
		r.Kind = "Resource"
	})
}
