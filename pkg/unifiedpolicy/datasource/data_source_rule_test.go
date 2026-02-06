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

// checkRuleAndTemplateDestroy verifies both rule and template from the test are destroyed (used when config has both).
func checkRuleAndTemplateDestroy(s *terraform.State) error {
	if err := acctest.TestAccCheckRuleDestroy("")(s); err != nil {
		return err
	}
	return acctest.TestAccCheckTemplateDestroy("")(s)
}

func TestAccRuleDataSource_basic(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rule.test"
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for rule datasource"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Test rule for datasource"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rule" "test" {
			id = %s.id
		}
	`, resourceConfig, resourceName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "id", resourceName, "id"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "name", resourceName, "name"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "description", resourceName, "description"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "template_id", resourceName, "template_id"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "name", name),
					resource.TestCheckResourceAttr(dataSourceFqrn, "description", "Test rule for datasource"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "id"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "is_custom"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "parameters.#", "0"),
				),
			},
		},
	})
}

func TestAccRuleDataSource_withParameters(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-rule-params-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rule.test"
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "params_severity_policy.rego")

	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template with parameters"
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
			description = "Test rule with parameters"
			template_id = unifiedpolicy_template.test.id
			parameters = [
				{ name = "severity_threshold", value = "high" },
				{ name = "max_count", value = "10" }
			]
		}
	`, templateName, regoPath, name, name)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rule" "test" {
			id = %s.id
		}
	`, resourceConfig, resourceName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceFqrn, "parameters.#", "2"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "parameters.0.name", "severity_threshold"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "parameters.0.value", "high"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "parameters.1.name", "max_count"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "parameters.1.value", "10"),
				),
			},
		},
	})
}

// TestAccRuleDataSource_notFound expects error when querying non-existent rule ID.
// Use a valid-format ID (fits int64, 4–20 digits) that does not exist so the server returns 404.
func TestAccRuleDataSource_notFound(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	config := `
		data "unifiedpolicy_rule" "test" {
			id = "999999999999999999"
		}
	`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Rule Not Found|not found|Invalid resource ID|Resource Not Found`),
			},
		},
	})
}

// TestAccRuleDataSource_withoutParameters reads a rule with no parameters (default empty).
func TestAccRuleDataSource_withoutParameters(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-rule-no-params-ds-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rule.test"
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	resourceConfig := fmt.Sprintf(`
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
			description = "Rule with no parameters"
			template_id = unifiedpolicy_template.test.id
		}
	`, templateName, regoPath, name, name)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rule" "test" {
			id = %s.id
		}
	`, resourceConfig, resourceName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "id", resourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "name", name),
					resource.TestCheckResourceAttr(dataSourceFqrn, "parameters.#", "0"),
				),
			},
		},
	})
}
