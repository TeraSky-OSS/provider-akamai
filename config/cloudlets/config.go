package cloudlets

import (
	"github.com/crossplane/upjet/pkg/config"
)

// Configure configures the cloudlets category resources.
func Configure(p *config.Provider) {
	p.AddResourceConfigurator("akamai_cloudlets_application_load_balancer", func(r *config.Resource) {
		r.ShortGroup = "cloudlets"
		r.Kind = "ApplicationLoadBalancer"
	})
	p.AddResourceConfigurator("akamai_cloudlets_application_load_balancer_activation", func(r *config.Resource) {
		r.ShortGroup = "cloudlets"
		r.Kind = "ApplicationLoadBalancerActivation"
	})
	p.AddResourceConfigurator("akamai_cloudlets_policy", func(r *config.Resource) {
		r.ShortGroup = "cloudlets"
		r.Kind = "Policy"
	})
	p.AddResourceConfigurator("akamai_cloudlets_policy_activation", func(r *config.Resource) {
		r.ShortGroup = "cloudlets"
		r.Kind = "PolicyActivation"
	})
}
