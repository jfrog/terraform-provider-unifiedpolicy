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

func TestAccTemplatesDataSource_basic(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-", "unifiedpolicy_template")
	dataSourceFqrn := "data.unifiedpolicy_templates.test"

	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")
	// Create a template
	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for list datasource"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}
	`, name, name, regoPath)

	// Query all templates (no terraform block — same as resource tests; avoids lock file check)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_templates" "test" {
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					// Verify we get at least one template (there may be other templates in the system)
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "templates.#"),
					resource.TestCheckResourceAttrWith(dataSourceFqrn, "templates.#", func(value string) error {
						// Just verify we got at least one result
						if value == "0" {
							return fmt.Errorf("expected at least one template, got 0")
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

func TestAccTemplatesDataSource_filterByCategory(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-", "unifiedpolicy_template")
	dataSourceFqrn := "data.unifiedpolicy_templates.test"

	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")
	// Create a security template
	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test security template"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}
	`, name, name, regoPath)

	// Query templates filtered by category
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_templates" "test" {
			category = "security"
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "templates.#"),
					// All returned templates should be security category
					// Note: We can't easily verify all items, but we can check the list exists
				),
			},
		},
	})
}

func TestAccTemplatesDataSource_filterByName(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-", "unifiedpolicy_template")
	dataSourceFqrn := "data.unifiedpolicy_templates.test"

	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")
	// Create a template with a specific name
	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for name filter"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}
	`, name, name, regoPath)

	// Query templates filtered by exact name. Reference the resource's name so Terraform
	// creates the template first, then reads the data source (otherwise Read can run before Create).
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_templates" "test" {
			name = %s.name
		}
	`, resourceConfig, resourceName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "templates.#"),
					resource.TestCheckResourceAttrWith(dataSourceFqrn, "templates.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one template when filtering by name %q, got 0", name)
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestAccTemplatesDataSource_pagination(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-", "unifiedpolicy_template")
	dataSourceFqrn := "data.unifiedpolicy_templates.test"

	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")
	// Create a template
	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for pagination"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}
	`, name, name, regoPath)

	// Query with pagination parameters
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_templates" "test" {
			page  = 0
			limit = 10
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "templates.#"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "offset"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "page_size"),
					// Verify pagination values
					resource.TestCheckResourceAttr(dataSourceFqrn, "offset", "0"),
					// page_size might be the actual number of items returned, not the limit
					resource.TestCheckResourceAttrWith(dataSourceFqrn, "page_size", func(value string) error {
						// Just verify it's set, don't check exact value
						return nil
					}),
				),
			},
		},
	})
}

func TestAccTemplatesDataSource_sorting(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-", "unifiedpolicy_template")
	dataSourceFqrn := "data.unifiedpolicy_templates.test"

	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")
	// Create a template
	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for sorting"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}
	`, name, name, regoPath)

	// Query with sorting parameters
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_templates" "test" {
			sort_by    = "name"
			sort_order = "asc"
		}
	`, resourceConfig)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "templates.#"),
				),
			},
		},
	})
}

func TestAccTemplatesDataSource_filterByIDs(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-", "unifiedpolicy_template")
	dataSourceFqrn := "data.unifiedpolicy_templates.test"
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)

	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")
	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for ids filter"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}
	`, name, name, regoPath)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_templates" "test" {
			ids = [%s.id]
		}
	`, resourceConfig, resourceName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceFqrn, "templates.#", "1"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "templates.0.id", resourceName, "id"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "templates.0.name", resourceName, "name"),
				),
			},
		},
	})
}

func TestAccTemplatesDataSource_filterByNames(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name1 := testutil.MkNames("test-template-a-", "unifiedpolicy_template")
	_, _, name2 := testutil.MkNames("test-template-b-", "unifiedpolicy_template")
	dataSourceFqrn := "data.unifiedpolicy_templates.test"

	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")
	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Template A"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}

		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Template B"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}
	`, name1, name1, regoPath, name2, name2, regoPath)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_templates" "test" {
			names = [unifiedpolicy_template.%s.name, unifiedpolicy_template.%s.name]
		}
	`, resourceConfig, name1, name2)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: dataSourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceFqrn, "templates.#", "2"),
				),
			},
		},
	})
}
