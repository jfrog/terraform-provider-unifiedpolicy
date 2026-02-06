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

const ruleEndpoint = "unifiedpolicy/api/v1/rules"

func TestAccRule_basic(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for rule"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Test rule for acceptance testing"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckRuleDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "description", "Test rule for acceptance testing"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "template_id"),
					resource.TestCheckResourceAttr(resourceName, "parameters.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "is_custom", "true"),
				),
			},
		},
	})
}

func TestAccRule_withParameters(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-rule-params-", "unifiedpolicy_rule")
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "params_severity_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template with parameters"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q

			parameters = [
				{
					name = "severity_threshold"
					type = "string"
				},
				{
					name = "max_count"
					type = "int"
				}
			]
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Test rule with parameters"
			template_id = unifiedpolicy_template.test.id
			parameters = [
				{
					name  = "severity_threshold"
					value = "high"
				},
				{
					name  = "max_count"
					value = "10"
				}
			]
		}
	`, templateName, regoPath, name, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckRuleDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "parameters.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.name", "severity_threshold"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.value", "high"),
					resource.TestCheckResourceAttr(resourceName, "parameters.1.name", "max_count"),
					resource.TestCheckResourceAttr(resourceName, "parameters.1.value", "10"),
				),
			},
		},
	})
}

// TestAccRule_withoutParameters tests that a rule can be created with only name and template_id; parameters defaults to empty.
func TestAccRule_withoutParameters(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-rule-no-params-", "unifiedpolicy_rule")
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for rule without params"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Test rule without parameters block"
			template_id = unifiedpolicy_template.test.id
		}
	`, templateName, regoPath, name, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckRuleDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "parameters.#", "0"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "template_id"),
				),
			},
		},
	})
}

func TestAccRule_withCustomFlag(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-rule-custom-", "unifiedpolicy_rule")
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

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

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Test rule with custom flag"
			template_id = unifiedpolicy_template.test.id
			is_custom   = true
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckRuleDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "is_custom", "true"),
				),
			},
		},
	})
}

func TestAccRule_update(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-rule-update-", "unifiedpolicy_rule")
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "params_severity_policy.rego")

	config1 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q

			parameters = [
				{
					name = "severity_threshold"
					type = "string"
				}
			]
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Initial description"
			template_id = unifiedpolicy_template.test.id
			parameters = [
				{
					name  = "severity_threshold"
					value = "critical"
				}
			]
		}
	`, templateName, regoPath, name, name)

	config2 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q

			parameters = [
				{
					name = "severity_threshold"
					type = "string"
				}
			]
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Updated description"
			template_id = unifiedpolicy_template.test.id
			parameters = [
				{
					name  = "severity_threshold"
					value = "high"
				}
			]
		}
	`, templateName, regoPath, name, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckRuleDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config1,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Initial description"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.value", "critical"),
				),
			},
			{
				Config: config2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.value", "high"),
				),
			},
		},
	})
}

func TestAccRule_updateParameters(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-rule-update-params-", "unifiedpolicy_rule")
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "params_multi_policy.rego")

	config1 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q

			parameters = [
				{
					name = "severity_threshold"
					type = "string"
				},
				{
					name = "max_count"
					type = "int"
				}
			]
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
			parameters = [
				{
					name  = "severity_threshold"
					value = "critical"
				},
				{
					name  = "max_count"
					value = "5"
				}
			]
		}
	`, templateName, regoPath, name, name)

	config2 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q

			parameters = [
				{
					name = "severity_threshold"
					type = "string"
				},
				{
					name = "max_count"
					type = "int"
				}
			]
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
			parameters = [
				{
					name  = "severity_threshold"
					value = "high"
				},
				{
					name  = "max_count"
					value = "10"
				}
			]
		}
	`, templateName, regoPath, name, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckRuleDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config1,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "parameters.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.value", "critical"),
					resource.TestCheckResourceAttr(resourceName, "parameters.1.value", "5"),
				),
			},
			{
				Config: config2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "parameters.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.value", "high"),
					resource.TestCheckResourceAttr(resourceName, "parameters.1.value", "10"),
				),
			},
		},
	})
}

func TestAccRule_import(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-rule-import-", "unifiedpolicy_rule")
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for import"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Test rule for import"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckRuleDestroy(fqrn),
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

func TestAccRule_withBooleanParameter(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-rule-bool-", "unifiedpolicy_rule")
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template with boolean parameter"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = [
				{
					name = "enabled"
					type = "bool"
				}
			]
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Test rule with boolean parameter"
			template_id = unifiedpolicy_template.test.id
			parameters = [
				{
					name  = "enabled"
					value = "true"
				}
			]
		}
	`, templateName, regoPath, name, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckRuleDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "parameters.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.name", "enabled"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.value", "true"),
				),
			},
		},
	})
}

func TestAccRule_withMultipleParameterTypes(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-rule-multi-param-", "unifiedpolicy_rule")
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "params_complex_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template with multiple parameter types"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q

			parameters = [
				{
					name = "severity"
					type = "string"
				},
				{
					name = "max_count"
					type = "int"
				},
				{
					name = "enabled"
					type = "bool"
				}
			]
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Test rule with multiple parameter types"
			template_id = unifiedpolicy_template.test.id
			parameters = [
				{
					name  = "severity"
					value = "high"
				},
				{
					name  = "max_count"
					value = "100"
				},
				{
					name  = "enabled"
					value = "false"
				}
			]
		}
	`, templateName, regoPath, name, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckRuleDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "parameters.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.name", "severity"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.value", "high"),
					resource.TestCheckResourceAttr(resourceName, "parameters.1.name", "max_count"),
					resource.TestCheckResourceAttr(resourceName, "parameters.1.value", "100"),
					resource.TestCheckResourceAttr(resourceName, "parameters.2.name", "enabled"),
					resource.TestCheckResourceAttr(resourceName, "parameters.2.value", "false"),
				),
			},
		},
	})
}

// TestAccRule_updateDescriptionToEmpty updates rule description to empty string.
func TestAccRule_updateDescriptionToEmpty(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-rule-desc-empty-", "unifiedpolicy_rule")
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	config1 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Initial description"
			template_id = unifiedpolicy_template.test.id
		}
	`, templateName, regoPath, name, name)

	config2 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = ""
			template_id = unifiedpolicy_template.test.id
		}
	`, templateName, regoPath, name, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckRuleDestroy(fqrn),
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

// TestAccRule_updateDescriptionRemoved updates rule to remove description (omit attribute).
func TestAccRule_updateDescriptionRemoved(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-rule-desc-remove-", "unifiedpolicy_rule")
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	config1 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Description to remove"
			template_id = unifiedpolicy_template.test.id
		}
	`, templateName, regoPath, name, name)

	config2 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
		}
	`, templateName, regoPath, name, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckRuleDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config1,
				Check:  resource.TestCheckResourceAttr(resourceName, "description", "Description to remove"),
			},
			{
				Config: config2,
				// After removing description, state has null (attribute unset); just verify resource exists.
				Check: resource.TestCheckResourceAttrSet(resourceName, "id"),
			},
		},
	})
}

// TestAccRule_createDuplicateName expects error when creating a second rule with the same name.
func TestAccRule_createDuplicateName(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, _ := testutil.MkNames("test-rule-dup-", "unifiedpolicy_rule")

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "a" {
			name        = "duplicate-rule-name-acctest"
			description = "First rule"
			template_id = unifiedpolicy_template.test.id
		}

		resource "unifiedpolicy_rule" "b" {
			name        = "duplicate-rule-name-acctest"
			description = "Second rule same name"
			template_id = unifiedpolicy_template.test.id
		}
	`, templateName, regoPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckRuleDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`already exists|Rule Already Exists|unique constraint|failed to create rule|Server [Ee]rror`),
			},
		},
	})
}

// TestAccRule_updateParametersAddThenRemove adds parameters then removes them.
func TestAccRule_updateParametersAddThenRemove(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-rule-params-lifecycle-", "unifiedpolicy_rule")
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "params_severity_policy.rego")

	config0 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = [
				{ name = "severity_threshold", type = "string" },
				{ name = "max_count", type = "int" }
			]
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
		}
	`, templateName, regoPath, name, name)

	config1 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = [
				{ name = "severity_threshold", type = "string" },
				{ name = "max_count", type = "int" }
			]
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
			parameters = [
				{ name = "severity_threshold", value = "high" },
				{ name = "max_count", value = "5" }
			]
		}
	`, templateName, regoPath, name, name)

	config2 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = [
				{ name = "severity_threshold", type = "string" },
				{ name = "max_count", type = "int" }
			]
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			template_id = unifiedpolicy_template.test.id
		}
	`, templateName, regoPath, name, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckRuleDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config0,
				Check:  resource.TestCheckResourceAttr(resourceName, "parameters.#", "0"),
			},
			{
				Config: config1,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "parameters.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.value", "high"),
					resource.TestCheckResourceAttr(resourceName, "parameters.1.value", "5"),
				),
			},
			{
				Config: config2,
				Check:  resource.TestCheckResourceAttr(resourceName, "parameters.#", "0"),
			},
		},
	})
}

func testAccCheckRuleDestroy(fqrn string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		restyClient, err := acctest.GetTestRestyFromEnv()
		if err != nil {
			return err
		}

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "unifiedpolicy_rule" {
				continue
			}

			response, err := restyClient.R().
				SetPathParam("rule_id", rs.Primary.ID).
				Get(ruleEndpoint + "/{rule_id}")

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
