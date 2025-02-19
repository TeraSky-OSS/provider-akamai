package clientlist

import (
	"github.com/crossplane/upjet/pkg/config"
)

// Configure configures the clientlist category resources.
func Configure(p *config.Provider) {
	p.AddResourceConfigurator("akamai_clientlist_activation", func(r *config.Resource) {
		r.ShortGroup = "clientlist"
		r.Kind = "Activation"
	})
	p.AddResourceConfigurator("akamai_clientlist_list", func(r *config.Resource) {
		r.ShortGroup = "clientlist"
		r.Kind = "List"
	})
}
