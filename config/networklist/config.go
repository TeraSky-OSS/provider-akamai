package networklist

import (
	"github.com/crossplane/upjet/pkg/config"
)

// Configure configures the network list category resources.
func Configure(p *config.Provider) {
	p.AddResourceConfigurator("akamai_networklist_activations", func(r *config.Resource) {
		r.ShortGroup = "networklist"
		r.Kind = "Activations"
	})
	p.AddResourceConfigurator("akamai_networklist_description", func(r *config.Resource) {
		r.ShortGroup = "networklist"
		r.Kind = "Description"
	})
	p.AddResourceConfigurator("akamai_networklist_network_list", func(r *config.Resource) {
		r.ShortGroup = "networklist"
		r.Kind = "NetworkList"
	})
	p.AddResourceConfigurator("akamai_networklist_subscription", func(r *config.Resource) {
		r.ShortGroup = "networklist"
		r.Kind = "Subscription"
	})
}
