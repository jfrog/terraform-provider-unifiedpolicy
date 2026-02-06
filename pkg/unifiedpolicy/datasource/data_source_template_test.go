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
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy/acctest"
)

func TestAccTemplateDataSource_basic(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-", "unifiedpolicy_template")
	dataSourceFqrn := "data.unifiedpolicy_template.test"
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)

	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")
	// First create the template
	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for datasource"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = []
		}
	`, name, name, regoPath)

	// Then query it (no terraform block — same as resource tests; avoids lock file check in temp dir)
	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_template" "test" {
			id = %s.id
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
					// Verify the data source attributes match the resource
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "id", resourceName, "id"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "name", resourceName, "name"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "description", resourceName, "description"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "category", resourceName, "category"),
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "data_source_type", resourceName, "data_source_type"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "name", name),
					resource.TestCheckResourceAttr(dataSourceFqrn, "description", "Test template for datasource"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "category", "security"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "rego"),
					resource.TestCheckResourceAttrSet(dataSourceFqrn, "is_custom"),
				),
			},
		},
	})
}

func TestAccTemplateDataSource_withParameters(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-params-", "unifiedpolicy_template")
	dataSourceFqrn := "data.unifiedpolicy_template.test"
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)

	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")
	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
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
	`, name, name, regoPath)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_template" "test" {
			id = %s.id
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
					resource.TestCheckResourceAttr(dataSourceFqrn, "parameters.#", "2"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "parameters.0.name", "severity_threshold"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "parameters.0.type", "string"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "parameters.1.name", "max_count"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "parameters.1.type", "int"),
				),
			},
		},
	})
}

func TestAccTemplateDataSource_withScanners(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-scanners-", "unifiedpolicy_template")
	dataSourceFqrn := "data.unifiedpolicy_template.test"
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)

	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")
	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template with scanners"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q

			parameters = []
			scanners = ["sca", "secrets", "exposures"]
		}
	`, name, name, regoPath)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_template" "test" {
			id = %s.id
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
					resource.TestCheckResourceAttr(dataSourceFqrn, "scanners.#", "3"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "scanners.0", "sca"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "scanners.1", "secrets"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "scanners.2", "exposures"),
				),
			},
		},
	})
}

// TestAccTemplateDataSource_notFound expects error when querying non-existent template ID.
// Use a valid-format ID (fits int64, 4–20 digits) that does not exist so the server returns 404.
func TestAccTemplateDataSource_notFound(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	config := `
		data "unifiedpolicy_template" "test" {
			id = "999999999999999999"
		}
	`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Template Not Found|not found|Invalid resource ID|Resource Not Found`),
			},
		},
	})
}

// TestAccTemplateDataSource_emptyDescription reads a template with no description.
func TestAccTemplateDataSource_emptyDescription(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-empty-desc-ds-", "unifiedpolicy_template")
	dataSourceFqrn := "data.unifiedpolicy_template.test"
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)

	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")
	resourceConfig := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, name, name, regoPath)

	dataSourceConfig := fmt.Sprintf(`
		%s

		data "unifiedpolicy_template" "test" {
			id = %s.id
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
					resource.TestCheckResourceAttrPair(dataSourceFqrn, "id", resourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceFqrn, "name", name),
					resource.TestCheckResourceAttr(dataSourceFqrn, "category", "security"),
				),
			},
		},
	})
}
