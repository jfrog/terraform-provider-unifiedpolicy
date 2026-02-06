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

package acctest

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/jfrog/terraform-provider-shared/client"
	"github.com/jfrog/terraform-provider-shared/testutil"
	provider "github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy/provider"
)

// ProtoV6ProviderFactories is used to instantiate the Framework provider
// during acceptance tests.
var ProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"unifiedpolicy": providerserver.NewProtocol6WithError(provider.Framework()()),
}

// RegoFixturePath returns the absolute path to a file under test-fixtures/. Tests are run
// from the module root, so the path is cwd/test-fixtures/filename. Use in acceptance test
// config for the rego attribute, e.g. rego = acctest.RegoFixturePath(t, "basic_policy.rego").
func RegoFixturePath(t *testing.T, filename string) string {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	return filepath.Join(cwd, "test-fixtures", filename)
}

// PreCheck This function should be present in every acceptance test.
func PreCheck(t *testing.T) {
	// Verify required environment variables are set
	_ = GetArtifactoryUrl(t)
	_ = GetAccessToken(t)
}

func GetArtifactoryUrl(t *testing.T) string {
	return testutil.GetEnvVarWithFallback(t, "JFROG_URL", "ARTIFACTORY_URL")
}

func GetAccessToken(t *testing.T) string {
	return testutil.GetEnvVarWithFallback(t, "JFROG_ACCESS_TOKEN", "ARTIFACTORY_ACCESS_TOKEN")
}

func GetTestResty(t *testing.T) *resty.Client {
	artifactoryUrl := GetArtifactoryUrl(t)
	restyClient, err := client.Build(artifactoryUrl, "")
	if err != nil {
		t.Fatal(err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	restyClient.SetTLSClientConfig(tlsConfig)
	restyClient.SetRetryCount(5)
	accessToken := GetAccessToken(t)
	restyClient, err = client.AddAuth(restyClient, "", accessToken)
	if err != nil {
		t.Fatal(err)
	}
	return restyClient
}

// GetTestRestyFromEnv builds a resty client from environment variables without requiring testing.T
// This is useful for CheckDestroy functions that don't have access to testing.T
func GetTestRestyFromEnv() (*resty.Client, error) {
	artifactoryUrl := testutil.GetEnvVarWithFallback(nil, "JFROG_URL", "ARTIFACTORY_URL")
	if artifactoryUrl == "" {
		return nil, fmt.Errorf("JFROG_URL or ARTIFACTORY_URL environment variable must be set")
	}

	restyClient, err := client.Build(artifactoryUrl, "")
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	restyClient.SetTLSClientConfig(tlsConfig)
	restyClient.SetRetryCount(5)
	accessToken := testutil.GetEnvVarWithFallback(nil, "JFROG_ACCESS_TOKEN", "ARTIFACTORY_ACCESS_TOKEN")
	if accessToken == "" {
		return nil, fmt.Errorf("JFROG_ACCESS_TOKEN or ARTIFACTORY_ACCESS_TOKEN environment variable must be set")
	}
	restyClient, err = client.AddAuth(restyClient, "", accessToken)
	if err != nil {
		return nil, err
	}
	return restyClient, nil
}

// SkipIfNotAcc skips the test if TF_ACC is not set
func SkipIfNotAcc(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Skipping acceptance test. Set TF_ACC=1 to run.")
	}
}

// Pre-created project keys (and app keys) for lifecycle policy acceptance tests.
// Projects aa, bb, cc, dd exist in the environment; each is attached to apptrust application aa, bb, cc, dd respectively.
const (
	LifecyclePolicyProjectKey1 = "aa"
	LifecyclePolicyProjectKey2 = "bb"
	LifecyclePolicyProjectKey3 = "cc"
	LifecyclePolicyProjectKey4 = "dd"
)

// TestAccCheckTemplateDestroy checks if a template resource has been destroyed
func TestAccCheckTemplateDestroy(fqrn string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		restyClient, err := GetTestRestyFromEnv()
		if err != nil {
			return err
		}

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "unifiedpolicy_template" {
				continue
			}

			response, err := restyClient.R().
				SetPathParam("templateId", rs.Primary.ID).
				Get("unifiedpolicy/api/v1/templates/{templateId}")

			if err != nil {
				return err
			}

			if response.StatusCode() == http.StatusNotFound {
				return nil
			}

			if response.IsSuccess() {
				return fmt.Errorf("template %s still exists", rs.Primary.ID)
			}
		}

		return nil
	}
}

// TestAccCheckRuleDestroy checks if a rule resource has been destroyed
func TestAccCheckRuleDestroy(fqrn string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		restyClient, err := GetTestRestyFromEnv()
		if err != nil {
			return err
		}

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "unifiedpolicy_rule" {
				continue
			}

			response, err := restyClient.R().
				SetPathParam("rule_id", rs.Primary.ID).
				Get("unifiedpolicy/api/v1/rules/{rule_id}")
			if err != nil {
				return err
			}

			if response.StatusCode() == http.StatusNotFound {
				return nil
			}

			if response.IsSuccess() {
				return fmt.Errorf("rule %s still exists", rs.Primary.ID)
			}
		}

		return nil
	}
}

// TestAccCheckLifecyclePolicyDestroy checks if a lifecycle policy resource has been destroyed.
func TestAccCheckLifecyclePolicyDestroy(fqrn string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		restyClient, err := GetTestRestyFromEnv()
		if err != nil {
			return err
		}

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "unifiedpolicy_lifecycle_policy" {
				continue
			}

			response, err := restyClient.R().
				SetPathParam("policyId", rs.Primary.ID).
				Get("unifiedpolicy/api/v1/policies/{policyId}")
			if err != nil {
				return err
			}

			if response.StatusCode() == http.StatusNotFound {
				return nil
			}

			if response.IsSuccess() {
				return fmt.Errorf("lifecycle policy %s still exists", rs.Primary.ID)
			}
		}

		return nil
	}
}
