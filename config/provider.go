/*
Copyright 2021 Upbound Inc.
*/

package config

import (
	// Note(turkenh): we are importing this to embed provider schema document
	_ "embed"

	ujconfig "github.com/crossplane/upjet/pkg/config"

	"github.com/terasky-oss/provider-akamai/config/appsecurity"
	"github.com/terasky-oss/provider-akamai/config/botman"
	"github.com/terasky-oss/provider-akamai/config/clientlist"
	"github.com/terasky-oss/provider-akamai/config/cloudlets"
	"github.com/terasky-oss/provider-akamai/config/cloudwrapper"
	"github.com/terasky-oss/provider-akamai/config/cps"
	"github.com/terasky-oss/provider-akamai/config/datastream"
	"github.com/terasky-oss/provider-akamai/config/dns"
	"github.com/terasky-oss/provider-akamai/config/edge"
	"github.com/terasky-oss/provider-akamai/config/gtm"
	"github.com/terasky-oss/provider-akamai/config/iam"
	"github.com/terasky-oss/provider-akamai/config/imagingpolicy"
	"github.com/terasky-oss/provider-akamai/config/networklist"
	"github.com/terasky-oss/provider-akamai/config/property"
)

const (
	resourcePrefix = "akamai"
	modulePath     = "github.com/terasky-oss/provider-akamai"
)

//go:embed schema.json
var providerSchema string

//go:embed provider-metadata.yaml
var providerMetadata string

// GetProvider returns provider configuration
func GetProvider() *ujconfig.Provider {
	pc := ujconfig.NewProvider([]byte(providerSchema), resourcePrefix, modulePath, []byte(providerMetadata),
		ujconfig.WithRootGroup("akamai.terasky.com"),
		ujconfig.WithIncludeList(ExternalNameConfigured()),
		ujconfig.WithFeaturesPackage("internal/features"),
		ujconfig.WithDefaultResourceOptions(
			ExternalNameConfigurations(),
		))

	for _, configure := range []func(provider *ujconfig.Provider){
		// add custom config functions
		appsecurity.Configure,
		botman.Configure,
		clientlist.Configure,
		cloudlets.Configure,
		cloudwrapper.Configure,
		cps.Configure,
		datastream.Configure,
		dns.Configure,
		edge.Configure,
		gtm.Configure,
		iam.Configure,
		imagingpolicy.Configure,
		networklist.Configure,
		property.Configure,
	} {
		configure(pc)
	}

	pc.ConfigureResources()
	return pc
}
