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

package datasource_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy/acctest"
)

// checkLifecyclePolicyRuleAndTemplateDestroy verifies policy, rule, and template from the test are destroyed.
func checkLifecyclePolicyRuleAndTemplateDestroy(s *terraform.State) error {
	if err := acctest.TestAccCheckLifecyclePolicyDestroy("")(s); err != nil {
		return err
	}
	if err := acctest.TestAccCheckRuleDestroy("")(s); err != nil {
		return err
	}
	return acctest.TestAccCheckTemplateDestroy("")(s)
}

func TestAccLifecyclePolicyDataSource_basic(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policy.test"
	resourceName := fmt.Sprintf("unifiedpolicy_lifecycle_policy.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	_, _, ruleName := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for policy datasource"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "test" {
			name        = "%s"
			description = "Test rule for policy datasource"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_lifecycle_policy" "%s" {
			name        = "%s"
			description = "Test policy for datasource"
			enabled    = true
			mode        = "block"

			action {
				type = "certify_to_gate"
				stage {
					key  = "PROD"
					gate = "release"
				}
			}

			scope {
				type         = "project"
				project_keys = ["%s"]
			}

			rule_ids = [unifiedpolicy_rule.test.id]
		}
	`, templateName, regoPath, ruleName, name, name, acctest.LifecyclePolicyProjectKey1)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_lifecycle_policy" "test" {
			id = %s.id
		}
	`, resourceConfig, resourceName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkLifecyclePolicyRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "id", resourceName, "id"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "name", resourceName, "name"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "description", resourceName, "description"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "enabled", resourceName, "enabled"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "mode", resourceName, "mode"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "name", name),
					resource.TestCheckResourceAttr(dataSourceFqrn, "description", "Test policy for datasource"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "enabled", "true"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "mode", "block"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "action.type", "certify_to_gate"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "action.stage.key", "PROD"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "action.stage.gate", "release"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "scope.type", "project"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "scope.project_keys.#", "1"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "scope.project_keys.0", acctest.LifecyclePolicyProjectKey1),
					resource.TestCheckResourceAttr(dataSourceFqrn, "rule_ids.#", "1"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "id"),
				),
			},
		},
	})
}

// TestAccLifecyclePolicyDataSource_notFound expects error when querying non-existent policy ID.
func TestAccLifecyclePolicyDataSource_notFound(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	config := `
		data "unifiedpolicy_lifecycle_policy" "test" {
			id = "999999999999999999"
		}
	`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Policy Not Found|not found|Invalid resource ID|Resource Not Found|Unable to Read`),
			},
		},
	})
}
