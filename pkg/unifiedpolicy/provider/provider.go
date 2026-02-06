// Copyright (c) JFrog Ltd. (2025)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package provider

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/client"
	"github.com/jfrog/terraform-provider-shared/util"
	validatorfw_string "github.com/jfrog/terraform-provider-shared/validator/fw/string"
	unifiedpolicy_datasource "github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy/datasource"
	unifiedpolicy_resource "github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy/resource"
)

var Version = "1.0.0" // needs to be exported so make file can update this
var productId = "terraform-provider-unifiedpolicy/" + Version

// Minimum required versions for Unified Policy
const (
	MinArtifactoryVersion = "7.125.0" // Minimum Artifactory version required for Unified Policy
	MinXrayVersion        = "3.130.5" // Minimum Xray version required for Unified Policy
)

var _ provider.Provider = (*UnifiedPolicyProvider)(nil)

// UnifiedPolicyProvider is the provider implementation for Unified Policy.
type UnifiedPolicyProvider struct{}

// UnifiedPolicyProviderModel describes the provider data model.
type UnifiedPolicyProviderModel struct {
	Url         types.String `tfsdk:"url"`
	AccessToken types.String `tfsdk:"access_token"`
	ApiKey      types.String `tfsdk:"api_key"`
}

func (p *UnifiedPolicyProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "unifiedpolicy"
	resp.Version = Version
}

func (p *UnifiedPolicyProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Description: "Artifactory URL.",
				Optional:    true,
				Validators: []validator.String{
					validatorfw_string.IsURLHttpOrHttps(),
				},
			},
			"access_token": schema.StringAttribute{
				Description: "This is a access token that can be given to you by your admin under `User Management -> Access Tokens`. If not set, the 'api_key' attribute value will be used.",
				Optional:    true,
				Sensitive:   true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"api_key": schema.StringAttribute{
				Description:        "API key. If `access_token` attribute, `JFROG_ACCESS_TOKEN` or `ARTIFACTORY_ACCESS_TOKEN` environment variable is set, the provider will ignore this attribute.",
				DeprecationMessage: "API Keys are deprecated. Please use access_token instead.",
				Optional:           true,
				Sensitive:          true,
			},
		},
	}
}

func (p *UnifiedPolicyProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	// Check environment variables for configuration
	// First available environment variable will be used
	url := util.CheckEnvVars([]string{"JFROG_URL", "ARTIFACTORY_URL"}, "")
	accessToken := util.CheckEnvVars([]string{"JFROG_ACCESS_TOKEN", "ARTIFACTORY_ACCESS_TOKEN"}, "")

	var config UnifiedPolicyProviderModel

	// Read configuration data into model
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.Url.ValueString() != "" {
		url = config.Url.ValueString()
	}

	if url == "" {
		resp.Diagnostics.AddError(
			"Missing URL Configuration",
			"While configuring the provider, the url was not found in "+
				"the JFROG_URL/ARTIFACTORY_URL environment variable or provider "+
				"configuration block url attribute.",
		)
		return
	}

	restyClient, err := client.Build(url, productId)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating Resty client",
			err.Error(),
		)
		return
	}

	// Configuration block values take precedence over environment variables
	if config.AccessToken.ValueString() != "" {
		accessToken = config.AccessToken.ValueString()
	}

	apiKey := config.ApiKey.ValueString()

	if apiKey == "" && accessToken == "" {
		resp.Diagnostics.AddError(
			"Missing JFrog API key or Access Token",
			"While configuring the provider, the API key or Access Token was not found in "+
				"the environment variables or provider configuration attributes.",
		)
		return
	}

	restyClient, err = client.AddAuth(restyClient, apiKey, accessToken)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error adding Auth to Resty client",
			err.Error(),
		)
		return
	}

	// Handle TLS verification bypass (for testing/development only)
	bypassJFrogTLSVerification := os.Getenv("JFROG_BYPASS_TLS_VERIFICATION")
	if strings.ToLower(bypassJFrogTLSVerification) == "true" {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		restyClient.SetTLSClientConfig(tlsConfig)
	}

	artifactoryVersion, err := util.GetArtifactoryVersion(restyClient)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error getting Artifactory version",
			fmt.Sprintf("The provider functionality might be affected by the absence of Artifactory version in the context. %v", err),
		)
		return
	}

	// Check Artifactory version compatibility
	minArtifactoryVersion, err := version.NewVersion(MinArtifactoryVersion)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid minimum Artifactory version",
			fmt.Sprintf("Failed to parse minimum required Artifactory version: %v", err),
		)
		return
	}

	currentArtifactoryVersion, err := version.NewVersion(artifactoryVersion)
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Unable to parse Artifactory version",
			fmt.Sprintf("Unable to parse Artifactory version '%s'. Version compatibility check skipped. %v", artifactoryVersion, err),
		)
	} else if currentArtifactoryVersion.LessThan(minArtifactoryVersion) {
		resp.Diagnostics.AddError(
			"Incompatible Artifactory version",
			fmt.Sprintf("Unified Policy requires Artifactory version %s or higher. Current version: %s", MinArtifactoryVersion, artifactoryVersion),
		)
		return
	}

	// Check Xray version compatibility
	xrayVersion, err := util.GetXrayVersion(restyClient)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error getting Xray version",
			fmt.Sprintf("Failed to get Xray version. Unified Policy requires Xray to be installed and accessible. %v", err),
		)
		return
	}

	minXrayVersion, err := version.NewVersion(MinXrayVersion)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid minimum Xray version",
			fmt.Sprintf("Failed to parse minimum required Xray version: %v", err),
		)
		return
	}

	currentXrayVersion, err := version.NewVersion(xrayVersion)
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Unable to parse Xray version",
			fmt.Sprintf("Unable to parse Xray version '%s'. Version compatibility check skipped. %v", xrayVersion, err),
		)
	} else if currentXrayVersion.LessThan(minXrayVersion) {
		resp.Diagnostics.AddError(
			"Incompatible Xray version",
			fmt.Sprintf("Unified Policy requires Xray version %s or higher. Current version: %s", MinXrayVersion, xrayVersion),
		)
		return
	}

	// Note: Unified Policy license validation is handled by the API itself.
	// If Unified Policy is not licensed or available, API calls will return appropriate errors.

	// Send usage telemetry (async)
	featureUsage := fmt.Sprintf("Terraform/%s", req.TerraformVersion)
	go util.SendUsage(ctx, restyClient.R(), productId, featureUsage)

	meta := util.ProviderMetadata{
		Client:             restyClient,
		ProductId:          productId,
		ArtifactoryVersion: artifactoryVersion,
		XrayVersion:        xrayVersion,
	}

	resp.DataSourceData = meta
	resp.ResourceData = meta
}

// Resources returns the list of resources supported by this provider.
func (p *UnifiedPolicyProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		unifiedpolicy_resource.NewLifecyclePolicyResource,
		unifiedpolicy_resource.NewRuleResource,
		unifiedpolicy_resource.NewTemplateResource,
	}
}

// DataSources returns the list of data sources supported by this provider.
func (p *UnifiedPolicyProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		unifiedpolicy_datasource.NewLifecyclePolicyDataSource,
		unifiedpolicy_datasource.NewLifecyclePoliciesDataSource,
		unifiedpolicy_datasource.NewRuleDataSource,
		unifiedpolicy_datasource.NewRulesDataSource,
		unifiedpolicy_datasource.NewTemplateDataSource,
		unifiedpolicy_datasource.NewTemplatesDataSource,
	}
}
