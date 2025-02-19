package datastream

import (
	"github.com/crossplane/upjet/pkg/config"
)

// Configure configures the datastream category resources.
func Configure(p *config.Provider) {
	p.AddResourceConfigurator("akamai_datastream", func(r *config.Resource) {
		r.ShortGroup = "datastream"
		r.Kind = "Datastream"
	})
}
