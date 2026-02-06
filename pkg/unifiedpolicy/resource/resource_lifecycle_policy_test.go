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

package resource_test

import (
	"fmt"
	"net/http"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy/acctest"
)

const policyEndpoint = "unifiedpolicy/api/v1/policies"

func TestAccLifecyclePolicy_basic(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	resourceName := fmt.Sprintf("unifiedpolicy_lifecycle_policy.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	_, _, ruleName := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description       = "Test template for lifecycle policy"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "test" {
			name        = "%s"
			description = "Test rule for lifecycle policy"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_lifecycle_policy" "%s" {
			name        = "%s"
			description = "Test lifecycle policy"
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

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckLifecyclePolicyDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "description", "Test lifecycle policy"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "mode", "block"),
					resource.TestCheckResourceAttr(resourceName, "action.type", "certify_to_gate"),
					resource.TestCheckResourceAttr(resourceName, "action.stage.key", "PROD"),
					resource.TestCheckResourceAttr(resourceName, "action.stage.gate", "release"),
					resource.TestCheckResourceAttr(resourceName, "scope.type", "project"),
					resource.TestCheckResourceAttr(resourceName, "scope.project_keys.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope.project_keys.0", acctest.LifecyclePolicyProjectKey1),
					resource.TestCheckResourceAttr(resourceName, "rule_ids.#", "1"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}

func TestAccLifecyclePolicy_withApplicationScope(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-policy-app-", "unifiedpolicy_lifecycle_policy")
	resourceName := fmt.Sprintf("unifiedpolicy_lifecycle_policy.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	_, _, ruleName := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description       = "Test template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "test" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_lifecycle_policy" "%s" {
			name        = "%s"
			description = "Test policy with application scope"
			enabled    = true
			mode        = "warning"

			action {
				type = "certify_to_gate"
				stage {
					key  = "PROD"
					gate = "release"
				}
			}

			scope {
				type             = "application"
				application_keys = ["%s"]
			}

			rule_ids = [unifiedpolicy_rule.test.id]
		}
	`, templateName, regoPath, ruleName, name, name, acctest.LifecyclePolicyProjectKey1)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckLifecyclePolicyDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "mode", "warning"),
					resource.TestCheckResourceAttr(resourceName, "scope.type", "application"),
					resource.TestCheckResourceAttr(resourceName, "scope.application_keys.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope.application_keys.0", acctest.LifecyclePolicyProjectKey1),
				),
			},
		},
	})
}

func TestAccLifecyclePolicy_withApplicationLabels(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-policy-labels-", "unifiedpolicy_lifecycle_policy")
	resourceName := fmt.Sprintf("unifiedpolicy_lifecycle_policy.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	_, _, ruleName := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description       = "Test template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "test" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_lifecycle_policy" "%s" {
			name        = "%s"
			description = "Test policy with application labels"
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
				type             = "application"
				application_keys = ["%s"]
				application_labels {
					key   = "environment"
					value = "production"
				}
				application_labels {
					key   = "team"
					value = "backend"
				}
			}

			rule_ids = [unifiedpolicy_rule.test.id]
		}
	`, templateName, regoPath, ruleName, name, name, acctest.LifecyclePolicyProjectKey2)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckLifecyclePolicyDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "scope.type", "application"),
					resource.TestCheckResourceAttr(resourceName, "scope.application_keys.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope.application_keys.0", acctest.LifecyclePolicyProjectKey2),
					resource.TestCheckResourceAttr(resourceName, "scope.application_labels.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scope.application_labels.0.key", "environment"),
					resource.TestCheckResourceAttr(resourceName, "scope.application_labels.0.value", "production"),
					resource.TestCheckResourceAttr(resourceName, "scope.application_labels.1.key", "team"),
					resource.TestCheckResourceAttr(resourceName, "scope.application_labels.1.value", "backend"),
				),
			},
		},
	})
}

func TestAccLifecyclePolicy_withMultipleRules(t *testing.T) {
	t.Skip("API allows only one rule per lifecycle policy (rule_ids max 1)")
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-policy-multi-rule-", "unifiedpolicy_lifecycle_policy")
	resourceName := fmt.Sprintf("unifiedpolicy_lifecycle_policy.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	_, _, rule1Name := testutil.MkNames("test-rule-1-", "unifiedpolicy_rule")
	_, _, rule2Name := testutil.MkNames("test-rule-2-", "unifiedpolicy_rule")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description       = "Test template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "test1" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_rule" "test2" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_lifecycle_policy" "%s" {
			name        = "%s"
			description = "Test policy with multiple rules"
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

			rule_ids = [unifiedpolicy_rule.test1.id, unifiedpolicy_rule.test2.id]
		}
	`, templateName, regoPath, rule1Name, rule2Name, name, name, acctest.LifecyclePolicyProjectKey4)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckLifecyclePolicyDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "rule_ids.#", "2"),
				),
			},
		},
	})
}

func TestAccLifecyclePolicy_update(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-policy-update-", "unifiedpolicy_lifecycle_policy")
	resourceName := fmt.Sprintf("unifiedpolicy_lifecycle_policy.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	_, _, ruleName := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	config1 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description       = "Test template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "test" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_lifecycle_policy" "%s" {
			name        = "%s"
			description = "Initial description"
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

	config2 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description       = "Test template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "test" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_lifecycle_policy" "%s" {
			name        = "%s"
			description = "Updated description"
			enabled    = false
			mode        = "warning"

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
	`, templateName, regoPath, ruleName, name, name, acctest.LifecyclePolicyProjectKey2)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckLifecyclePolicyDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config1,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Initial description"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "mode", "block"),
					resource.TestCheckResourceAttr(resourceName, "action.stage.key", "PROD"),
					resource.TestCheckResourceAttr(resourceName, "action.stage.gate", "release"),
					resource.TestCheckResourceAttr(resourceName, "scope.project_keys.#", "1"),
				),
			},
			{
				Config: config2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "mode", "warning"),
					resource.TestCheckResourceAttr(resourceName, "action.stage.key", "PROD"),
					resource.TestCheckResourceAttr(resourceName, "action.stage.gate", "release"),
					resource.TestCheckResourceAttr(resourceName, "scope.project_keys.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scope.project_keys.0", acctest.LifecyclePolicyProjectKey2),
				),
			},
		},
	})
}

func TestAccLifecyclePolicy_import(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-policy-import-", "unifiedpolicy_lifecycle_policy")
	resourceName := fmt.Sprintf("unifiedpolicy_lifecycle_policy.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	_, _, ruleName := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description       = "Test template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "test" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_lifecycle_policy" "%s" {
			name        = "%s"
			description = "Test policy for import"
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
	`, templateName, regoPath, ruleName, name, name, acctest.LifecyclePolicyProjectKey3)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckLifecyclePolicyDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccLifecyclePolicy_updateDescriptionToEmpty(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-policy-desc-", "unifiedpolicy_lifecycle_policy")
	resourceName := fmt.Sprintf("unifiedpolicy_lifecycle_policy.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	_, _, ruleName := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	config1 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "test" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_lifecycle_policy" "%s" {
			name        = "%s"
			description = "Initial description"
			enabled     = true
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

	config2 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "test" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_lifecycle_policy" "%s" {
			name        = "%s"
			description = ""
			enabled     = true
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

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckLifecyclePolicyDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config1,
				Check:  resource.TestCheckResourceAttr(resourceName, "description", "Initial description"),
			},
			{
				Config: config2,
				Check:  resource.TestCheckResourceAttr(resourceName, "description", ""),
			},
		},
	})
}

func TestAccLifecyclePolicy_createDuplicateName(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-dup-", "unifiedpolicy_lifecycle_policy")

	_, _, templateName := testutil.MkNames("test-template-", "template")
	_, _, ruleName := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	// Two policies with the same name should fail (API typically enforces unique name).
	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "test" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_lifecycle_policy" "a" {
			name        = "%s"
			description = "First"
			enabled     = true
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

		resource "unifiedpolicy_lifecycle_policy" "b" {
			name        = "%s"
			description = "Second"
			enabled     = true
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
	`, templateName, regoPath, ruleName, name, acctest.LifecyclePolicyProjectKey1, name, acctest.LifecyclePolicyProjectKey2)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Policy Already Exists|already exists|Conflict|unique|duplicate`),
			},
		},
	})
}

func testAccCheckLifecyclePolicyDestroy(fqrn string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		restyClient, err := acctest.GetTestRestyFromEnv()
		if err != nil {
			return err
		}

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "unifiedpolicy_lifecycle_policy" {
				continue
			}

			response, err := restyClient.R().
				SetPathParam("policyId", rs.Primary.ID).
				Get(policyEndpoint + "/{policyId}")

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
