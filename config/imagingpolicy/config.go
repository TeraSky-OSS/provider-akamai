package imagingpolicy

import (
	"github.com/crossplane/upjet/pkg/config"
)

// Configure configures the imaging policy category resources.
func Configure(p *config.Provider) {
	p.AddResourceConfigurator("akamai_imaging_policy_image", func(r *config.Resource) {
		r.ShortGroup = "imaging"
		r.Kind = "PolicyImage"
	})
	p.AddResourceConfigurator("akamai_imaging_policy_set", func(r *config.Resource) {
		r.ShortGroup = "imaging"
		r.Kind = "PolicySet"
	})
	p.AddResourceConfigurator("akamai_imaging_policy_video", func(r *config.Resource) {
		r.ShortGroup = "imaging"
		r.Kind = "PolicyVideo"
	})
}
