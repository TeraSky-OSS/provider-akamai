package dns

import (
	"github.com/crossplane/upjet/pkg/config"
)

// Configure configures the DNS category resources.
func Configure(p *config.Provider) {
	p.AddResourceConfigurator("akamai_dns_record", func(r *config.Resource) {
		r.ShortGroup = "dns"
		r.Kind = "Record"
	})
	p.AddResourceConfigurator("akamai_dns_zone", func(r *config.Resource) {
		r.ShortGroup = "dns"
		r.Kind = "Zone"
	})
}
