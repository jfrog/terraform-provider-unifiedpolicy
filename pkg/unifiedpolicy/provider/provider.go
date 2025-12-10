package provider

var Version = "1.0.0" // needs to be exported so make file can update this
var productId = "terraform-provider-unifiedpolicy/" + Version

// Minimum required versions for Unified Policy
const (
	MinArtifactoryVersion = "7.125.0" // Minimum Artifactory version required for Unified Policy
	MinXrayVersion        = "3.130.5" // Minimum Xray version required for Unified Policy
)
