package edge

import (
	"github.com/crossplane/upjet/pkg/config"
)

// Configure configures the edge category resources.
func Configure(p *config.Provider) {
	p.AddResourceConfigurator("akamai_edge_hostname", func(r *config.Resource) {
		r.ShortGroup = "edge"
		r.Kind = "Hostname"
	})
	p.AddResourceConfigurator("akamai_edgekv", func(r *config.Resource) {
		r.ShortGroup = "edgekv"
		r.Kind = "EdgeKV"
	})
	p.AddResourceConfigurator("akamai_edgekv_group_items", func(r *config.Resource) {
		r.ShortGroup = "edgekv"
		r.Kind = "GroupItems"
	})
	p.AddResourceConfigurator("akamai_edgeworker", func(r *config.Resource) {
		r.ShortGroup = "edgeworker"
		r.Kind = "EdgeWorker"
	})
	p.AddResourceConfigurator("akamai_edgeworkers_activation", func(r *config.Resource) {
		r.ShortGroup = "edgeworker"
		r.Kind = "Activation"
	})
}
