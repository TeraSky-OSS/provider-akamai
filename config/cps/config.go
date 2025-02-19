package cps

import (
	"github.com/crossplane/upjet/pkg/config"
)

// Configure configures the CPS category resources.
func Configure(p *config.Provider) {
	p.AddResourceConfigurator("akamai_cp_code", func(r *config.Resource) {
		r.ShortGroup = "cp"
		r.Kind = "Code"
	})
	p.AddResourceConfigurator("akamai_cps_dv_enrollment", func(r *config.Resource) {
		r.ShortGroup = "cps"
		r.Kind = "DvEnrollment"
	})
	p.AddResourceConfigurator("akamai_cps_dv_validation", func(r *config.Resource) {
		r.ShortGroup = "cps"
		r.Kind = "DvValidation"
	})
	p.AddResourceConfigurator("akamai_cps_third_party_enrollment", func(r *config.Resource) {
		r.ShortGroup = "cps"
		r.Kind = "ThirdPartyEnrollment"
	})
	p.AddResourceConfigurator("akamai_cps_upload_certificate", func(r *config.Resource) {
		r.ShortGroup = "cps"
		r.Kind = "UploadCertificate"
	})
}
