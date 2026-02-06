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

func lifecyclePolicyListConfig(t *testing.T, name string) string {
	_, _, templateName := testutil.MkNames("test-template-", "template")
	_, _, ruleName := testutil.MkNames("test-rule-", "unifiedpolicy_rule")
	regoPath := acctest.RegoFixturePath(t, "basic_policy.rego")
	return fmt.Sprintf(`
		resource "unifiedpolicy_template" "test" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for list policies"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_rule" "test" {
			name        = "%s"
			description = "Test rule for list policies"
			template_id = unifiedpolicy_template.test.id
			parameters  = []
		}

		resource "unifiedpolicy_lifecycle_policy" "%s" {
			name        = "%s"
			description = "Test policy for list datasource"
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
}

func TestAccLifecyclePoliciesDataSource_basic(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policies.test"

	resourceConfig := lifecyclePolicyListConfig(t, name)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_lifecycle_policies" "test" {
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkLifecyclePolicyRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "policies.#"),
					resource.TestCheckResourceAttrWith(dataSourceFqrn, "policies.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one policy, got 0")
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

func TestAccLifecyclePoliciesDataSource_filterByID(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policies.test"
	resourceName := fmt.Sprintf("unifiedpolicy_lifecycle_policy.%s", name)

	resourceConfig := lifecyclePolicyListConfig(t, name)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_lifecycle_policies" "test" {
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
					resource.TestCheckResourceAttr(dataSourceFqrn, "policies.#", "1"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "policies.0.id", resourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "policies.0.name", name),
				),
			},
		},
	})
}

func TestAccLifecyclePoliciesDataSource_filterByIds(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policies.test"
	resourceName := fmt.Sprintf("unifiedpolicy_lifecycle_policy.%s", name)

	resourceConfig := lifecyclePolicyListConfig(t, name)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_lifecycle_policies" "test" {
			ids = [%s.id]
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
					resource.TestCheckResourceAttr(dataSourceFqrn, "policies.#", "1"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "policies.0.id", resourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "policies.0.name", name),
				),
			},
		},
	})
}

func TestAccLifecyclePoliciesDataSource_filterByName(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policies.test"
	resourceName := fmt.Sprintf("unifiedpolicy_lifecycle_policy.%s", name)

	resourceConfig := lifecyclePolicyListConfig(t, name)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_lifecycle_policies" "test" {
			name = %s.name
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
					resource.TestCheckResourceAttr(dataSourceFqrn, "policies.#", "1"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "policies.0.name", name),
				),
			},
		},
	})
}

func TestAccLifecyclePoliciesDataSource_filterByNames(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policies.test"
	resourceName := fmt.Sprintf("unifiedpolicy_lifecycle_policy.%s", name)

	resourceConfig := lifecyclePolicyListConfig(t, name)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_lifecycle_policies" "test" {
			names = [%s.name]
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
					resource.TestCheckResourceAttr(dataSourceFqrn, "policies.#", "1"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "policies.0.name", name),
				),
			},
		},
	})
}

func TestAccLifecyclePoliciesDataSource_filterByEnabled(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policies.test"

	resourceConfig := lifecyclePolicyListConfig(t, name)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_lifecycle_policies" "test" {
			enabled = true
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkLifecyclePolicyRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "policies.#"),
					resource.TestCheckResourceAttrWith(dataSourceFqrn, "policies.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one enabled policy, got 0")
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestAccLifecyclePoliciesDataSource_filterByMode(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policies.test"

	resourceConfig := lifecyclePolicyListConfig(t, name)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_lifecycle_policies" "test" {
			mode = "block"
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkLifecyclePolicyRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "policies.#"),
				),
			},
		},
	})
}

func TestAccLifecyclePoliciesDataSource_filterByScopeType(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policies.test"

	resourceConfig := lifecyclePolicyListConfig(t, name)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_lifecycle_policies" "test" {
			scope_type = "project"
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkLifecyclePolicyRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "policies.#"),
				),
			},
		},
	})
}

func TestAccLifecyclePoliciesDataSource_filterByProjectKey(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policies.test"

	resourceConfig := lifecyclePolicyListConfig(t, name)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_lifecycle_policies" "test" {
			project_key = "%s"
		}
	`, resourceConfig, acctest.LifecyclePolicyProjectKey1)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkLifecyclePolicyRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "policies.#"),
					resource.TestCheckResourceAttrWith(dataSourceFqrn, "policies.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one policy for project %s, got 0", acctest.LifecyclePolicyProjectKey1)
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestAccLifecyclePoliciesDataSource_pagination(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policies.test"

	resourceConfig := lifecyclePolicyListConfig(t, name)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_lifecycle_policies" "test" {
			page  = 0
			limit = 10
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkLifecyclePolicyRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "policies.#"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "offset"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "page_size"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "offset", "0"),
				),
			},
		},
	})
}

func TestAccLifecyclePoliciesDataSource_sorting(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policies.test"

	resourceConfig := lifecyclePolicyListConfig(t, name)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_lifecycle_policies" "test" {
			sort_by   = "name"
			sort_order = "asc"
			limit     = 5
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkLifecyclePolicyRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "policies.#"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "offset"),
				),
			},
		},
	})
}

func TestAccLifecyclePoliciesDataSource_expandRules(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policies.test"

	resourceConfig := lifecyclePolicyListConfig(t, name)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_lifecycle_policies" "test" {
			expand = "rules"
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             checkLifecyclePolicyRuleAndTemplateDestroy,
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "policies.#"),
					resource.TestCheckResourceAttrWith(dataSourceFqrn, "policies.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one policy, got 0")
						}
						return nil
					}),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "offset"),
				),
			},
		},
	})
}

func TestAccLifecyclePoliciesDataSource_multiFilter(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, _, name := testutil.MkNames("test-policy-", "unifiedpolicy_lifecycle_policy")
	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policies.test"
	resourceName := fmt.Sprintf("unifiedpolicy_lifecycle_policy.%s", name)

	resourceConfig := lifecyclePolicyListConfig(t, name)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_lifecycle_policies" "test" {
			id         = %s.id
			enabled    = true
			mode       = "block"
			scope_type = "project"
			limit      = 10
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
					resource.TestCheckResourceAttr(dataSourceFqrn, "policies.#", "1"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "policies.0.id", resourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "policies.0.enabled", "true"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "policies.0.mode", "block"),
				),
			},
		},
	})
}

// TestAccLifecyclePoliciesDataSource_filterByIDNonexistent verifies empty list when filtering by non-existent ID.
func TestAccLifecyclePoliciesDataSource_filterByIDNonexistent(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	dataSourceFqrn := "data.unifiedpolicy_lifecycle_policies.test"

	config := `
		data "unifiedpolicy_lifecycle_policies" "test" {
			id = "999999999999999999"
		}
	`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceFqrn, "policies.#", "0"),
				),
			},
		},
	})
}
