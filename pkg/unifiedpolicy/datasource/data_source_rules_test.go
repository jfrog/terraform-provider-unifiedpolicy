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
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy/acctest"
)

func TestAccRulesDataSource_basic(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rules.test"

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for list rules"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Test rule for list datasource"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rules" "test" {
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "rules.#"),
					resource.TestCheckResourceAttrWith(dataSourceFqrn, "rules.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one rule, got 0")
						}
						return nil
					}),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "offset"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "page_size"),
				),
			},
		},
	})
}

func TestAccRulesDataSource_filterByName(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rules.test"
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	resourceConfig := fmt.Sprintf(`
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
			description = "Test rule for name filter"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rules" "test" {
			name = %s.name
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
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "rules.#"),
					resource.TestCheckResourceAttrWith(dataSourceFqrn, "rules.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one rule when filtering by name %q, got 0", name)
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestAccRulesDataSource_filterByID(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rules.test"
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	resourceConfig := fmt.Sprintf(`
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
			description = "Test rule for id filter"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rules" "test" {
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
					resource.TestCheckResourceAttr(dataSourceFqrn, "rules.#", "1"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "rules.0.id", resourceName, "id"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "rules.0.name", resourceName, "name"),
				),
			},
		},
	})
}

func TestAccRulesDataSource_filterByIDs(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rules.test"
	resourceName := fmt.Sprintf("unifiedpolicy_rule.%s", name)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	resourceConfig := fmt.Sprintf(`
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
			description = "Test rule for ids filter"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	// Filter by single rule ID via ids = [resource.id]
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rules" "test" {
			ids = [%s.id]
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
					resource.TestCheckResourceAttr(dataSourceFqrn, "rules.#", "1"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "rules.0.id", resourceName, "id"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "rules.0.name", resourceName, "name"),
				),
			},
		},
	})
}

func TestAccRulesDataSource_filterByMultipleIDs(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name1 := testutil.MkNames("test-rule-a-", "unifiedpolicy_rule")
	_, _, name2 := testutil.MkNames("test-rule-b-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rules.test"
	resourceName1 := fmt.Sprintf("unifiedpolicy_rule.%s", name1)
	resourceName2 := fmt.Sprintf("unifiedpolicy_rule.%s", name2)

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	resourceConfig := fmt.Sprintf(`
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
			description = "Rule A"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Rule B"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name1, name1, name2, name2)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rules" "test" {
			ids = [%s.id, %s.id]
		}
	`, resourceConfig, resourceName1, resourceName2)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceFqrn, "rules.#", "2"),
				),
			},
		},
	})
}

func TestAccRulesDataSource_filterByNames(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name1 := testutil.MkNames("test-rule-x-", "unifiedpolicy_rule")
	_, _, name2 := testutil.MkNames("test-rule-y-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rules.test"

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	resourceConfig := fmt.Sprintf(`
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
			description = "Rule X"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Rule Y"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name1, name1, name2, name2)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rules" "test" {
			names = [unifiedpolicy_rule.%s.name, unifiedpolicy_rule.%s.name]
		}
	`, resourceConfig, name1, name2)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceFqrn, "rules.#", "2"),
				),
			},
		},
	})
}

func TestAccRulesDataSource_filterByScannerTypes(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)
	t.Skip("Server returns 500 when scanner_types filter is used (backend encode bug); re-enable when API is fixed")

	_, _, name := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rules.test"

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")

	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Template with scanners"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
			scanners         = ["sca", "secrets"]
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Rule for scanner_types filter"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rules" "test" {
			scanner_types = ["sca", "secrets"]
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "rules.#"),
				),
			},
		},
	})
}

func TestAccRulesDataSource_filterByTemplateCategory(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)
	t.Skip("Server returns 500 when template_category filter is used (backend encode bug); re-enable when API is fixed")

	_, _, name := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rules.test"

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Security template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Rule for category filter"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rules" "test" {
			template_category = "security"
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "rules.#"),
				),
			},
		},
	})
}

func TestAccRulesDataSource_filterByTemplateDataSource(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rules.test"

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Template with data source"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Rule for template_data_source filter"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rules" "test" {
			template_data_source = "evidence"
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "rules.#"),
				),
			},
		},
	})
}

func TestAccRulesDataSource_expand(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rules.test"

	_, _, templateName := testutil.MkNames("test-template-", "template")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")

	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Template for expand"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "%s" {
			name        = "%s"
			description = "Rule for expand filter"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rules" "test" {
			expand = "template"
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "rules.#"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "offset"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "page_size"),
				),
			},
		},
	})
}

func TestAccRulesDataSource_multiFilter(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)
	t.Skip("Server returns 500 when template_category is used in rules list (backend encode bug); re-enable when API is fixed")

	_, _, name := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rules.test"

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
			description = "Rule for multi filter"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rules" "test" {
			template_category = "security"
			limit              = 25
			page               = 0
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "rules.#"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "offset"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "offset", "0"),
				),
			},
		},
	})
}

func TestAccRulesDataSource_pagination(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rules.test"

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
			description = "Rule for pagination"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rules" "test" {
			page  = 0
			limit = 10
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "rules.#"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "offset"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "page_size"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "offset", "0"),
				),
			},
		},
	})
}

func TestAccRulesDataSource_sorting(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	dataSourceFqrn := "data.unifiedpolicy_rules.test"

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
			description = "Rule for sorting"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}
	`, templateName, regoPath, name, name)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_rules" "test" {
			sort_by    = "name"
			sort_order = "asc"
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "rules.#"),
				),
			},
		},
	})
}
