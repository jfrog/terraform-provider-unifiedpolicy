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
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy/acctest"
	unifiedpolicyresource "github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy/resource"
	"github.com/open-policy-agent/opa/v1/ast"
)

const templateEndpoint = "unifiedpolicy/api/v1/templates"

func TestAccTemplate_basic(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-", "unifiedpolicy_template")
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)
	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for acceptance testing"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, name, name, regoPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "description", "Test template for acceptance testing"),
					resource.TestCheckResourceAttr(resourceName, "category", "security"),
					resource.TestCheckResourceAttr(resourceName, "data_source_type", "evidence"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "rego"),
					resource.TestCheckResourceAttr(resourceName, "is_custom", "true"),
				),
			},
		},
	})
}

func TestAccTemplate_withParameters(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-params-", "unifiedpolicy_template")
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)
	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")

	config := fmt.Sprintf(`
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

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "category", "security"),
					resource.TestCheckResourceAttr(resourceName, "parameters.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.name", "severity_threshold"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.type", "string"),
					resource.TestCheckResourceAttr(resourceName, "parameters.1.name", "max_count"),
					resource.TestCheckResourceAttr(resourceName, "parameters.1.type", "int"),
				),
			},
		},
	})
}

func TestAccTemplate_withScanners(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-scanners-", "unifiedpolicy_template")
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)
	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template with scanners"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
			scanners         = ["sca", "secrets"]
		}
	`, name, name, regoPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "scanners.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scanners.0", "sca"),
					resource.TestCheckResourceAttr(resourceName, "scanners.1", "secrets"),
				),
			},
		},
	})
}

func TestAccTemplate_update(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-update-", "unifiedpolicy_template")
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)
	regoPath1 := acctest.RegoFixturePath(t, "update_policy_v1.rego")
	regoPath2 := acctest.RegoFixturePath(t, "update_policy_v2.rego")

	config1 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Initial description"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, name, name, regoPath1)

	config2 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Updated description"
			category         = "quality"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, name, name, regoPath2)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config1,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Initial description"),
					resource.TestCheckResourceAttr(resourceName, "category", "security"),
				),
			},
			{
				Config: config2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
					resource.TestCheckResourceAttr(resourceName, "category", "quality"),
				),
			},
		},
	})
}

func TestAccTemplate_import(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-import-", "unifiedpolicy_template")
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)
	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Test template for import"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, name, name, regoPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"rego"}, // API returns rego content (or empty), not the file path from config
			},
		},
	})
}

// TestAccTemplate_withoutParameters tests that parameters defaults to empty array when omitted
func TestAccTemplate_withoutParameters(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-no-params-", "unifiedpolicy_template")
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)
	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
		}
	`, name, name, regoPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "parameters.#", "0"),
				),
			},
		},
	})
}

// TestAccTemplate_withoutScanners tests that scanners defaults to empty array
func TestAccTemplate_withoutScanners(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-no-scanners-", "unifiedpolicy_template")
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)
	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, name, name, regoPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "scanners.#", "0"),
				),
			},
		},
	})
}

// TestAccTemplate_emptyDescription tests that empty description string is handled correctly
func TestAccTemplate_emptyDescription(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-empty-desc-", "unifiedpolicy_template")
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)
	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = ""
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, name, name, regoPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", ""),
				),
			},
		},
	})
}

// TestAccTemplate_withAllowedRegoOperations tests that allowed Rego operations work
func TestAccTemplate_withAllowedRegoOperations(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-allowed-ops-", "unifiedpolicy_template")
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)
	regoPath := acctest.RegoFixturePath(t, "complex_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, name, name, regoPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "rego"),
				),
			},
		},
	})
}

// TestAccTemplate_updateDescriptionToEmpty tests updating description to empty string
func TestAccTemplate_updateDescriptionToEmpty(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-desc-update-", "unifiedpolicy_template")
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)
	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")

	config1 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Initial description"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, name, name, regoPath)

	config2 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = ""
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, name, name, regoPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config1,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Initial description"),
				),
			},
			{
				Config: config2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", ""),
				),
			},
		},
	})
}

// TestAccTemplate_updateDescriptionRemoved tests removing description (should be null)
func TestAccTemplate_updateDescriptionRemoved(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-desc-remove-", "unifiedpolicy_template")
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)
	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")

	config1 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			description      = "Initial description"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, name, name, regoPath)

	config2 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, name, name, regoPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config1,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Initial description"),
				),
			},
			{
				Config: config2,
				Check: resource.ComposeTestCheckFunc(
					// Description should be removed (null) - Terraform will show as empty in state
					resource.TestCheckNoResourceAttr(resourceName, "description"),
				),
			},
		},
	})
}

// TestAccTemplate_createDuplicateName expects error when creating two templates with the same name (if API enforces uniqueness).
func TestAccTemplate_createDuplicateName(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, _ := testutil.MkNames("test-template-dup-", "unifiedpolicy_template")
	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")

	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "a" {
			name             = "duplicate-template-name-acctest"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}

		resource "unifiedpolicy_template" "b" {
			name             = "duplicate-template-name-acctest"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, regoPath, regoPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`already exists|conflict|duplicate|409`),
			},
		},
	})
}

// TestAccTemplate_updateParametersAddThenRemove adds parameters then removes them.
func TestAccTemplate_updateParametersAddThenRemove(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-params-lifecycle-", "unifiedpolicy_template")
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)
	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")

	config0 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
		}
	`, name, name, regoPath)

	config1 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters = [
				{ name = "severity_threshold", type = "string" },
				{ name = "max_count", type = "int" }
			]
		}
	`, name, name, regoPath)

	config2 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
		}
	`, name, name, regoPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config0,
				Check:  resource.TestCheckResourceAttr(resourceName, "parameters.#", "0"),
			},
			{
				Config: config1,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "parameters.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.name", "severity_threshold"),
					resource.TestCheckResourceAttr(resourceName, "parameters.1.name", "max_count"),
				),
			},
			{
				Config: config2,
				Check:  resource.TestCheckResourceAttr(resourceName, "parameters.#", "0"),
			},
		},
	})
}

// TestAccTemplate_updateScannersAddThenRemove adds scanners then removes them.
func TestAccTemplate_updateScannersAddThenRemove(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	_, fqrn, name := testutil.MkNames("test-template-scanners-lifecycle-", "unifiedpolicy_template")
	resourceName := fmt.Sprintf("unifiedpolicy_template.%s", name)
	regoPath := acctest.RegoFixturePath(t, "params_policy.rego")

	config0 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, name, name, regoPath)

	config1 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
			scanners         = ["sca", "secrets"]
		}
	`, name, name, regoPath)

	config2 := fmt.Sprintf(`
		resource "unifiedpolicy_template" "%s" {
			name             = "%s"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, name, name, regoPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.TestAccCheckTemplateDestroy(fqrn),
		Steps: []resource.TestStep{
			{
				Config: config0,
				Check:  resource.TestCheckResourceAttr(resourceName, "scanners.#", "0"),
			},
			{
				Config: config1,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "scanners.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "scanners.0", "sca"),
					resource.TestCheckResourceAttr(resourceName, "scanners.1", "secrets"),
				),
			},
			{
				Config: config2,
				Check:  resource.TestCheckResourceAttr(resourceName, "scanners.#", "0"),
			},
		},
	})
}

// Unit tests for Rego validator functions

func TestGetAllowedRegoOperations(t *testing.T) {
	allowedOps := unifiedpolicyresource.GetAllowedRegoOperations()

	// Test that some expected allowed operations are present
	expectedAllowed := []string{
		"eq", "equal", "neq", "gt", "lt",
		"count", "sum", "max", "min",
		"array.concat", "array.reverse",
		"object.get", "object.keys",
		"json.unmarshal", "json.patch",
		"base64.encode", "base64.decode",
		"time.now_ns", "time.parse_ns",
		"regex.match", "regex.split",
		"is_number", "is_string", "is_boolean",
	}

	for _, op := range expectedAllowed {
		if !allowedOps[op] {
			t.Errorf("Expected operation %s to be allowed, but it was not found", op)
		}
	}

	// Test that some disallowed operations are not present
	expectedDisallowed := []string{
		"http.send", "io.jwt.decode", "rand.intn",
		"os.getenv", "net.lookup_ip_addr",
	}

	for _, op := range expectedDisallowed {
		if allowedOps[op] {
			t.Errorf("Expected operation %s to be disallowed, but it was found in allowed list", op)
		}
	}
}

func TestFindDisallowedOperations(t *testing.T) {
	allowedOps := unifiedpolicyresource.GetAllowedRegoOperations()

	tests := []struct {
		name           string
		regoCode       string
		expectedErrors []string
	}{
		{
			name: "valid operations only",
			regoCode: `package unifiedpolicy
default allow = false
allow {
    input.evidence.severity != "critical"
    count(input.evidence.vulnerabilities) > 0
    array.concat(input.list1, input.list2)
}`,
			expectedErrors: []string{},
		},
		{
			name: "invalid http.send",
			regoCode: `package unifiedpolicy
default allow = false
allow {
    http.send({"method": "GET", "url": "https://example.com"})
}`,
			expectedErrors: []string{"http.send"},
		},
		{
			name: "invalid io.jwt.decode",
			regoCode: `package unifiedpolicy
default allow = false
allow {
    io.jwt.decode(input.token)
}`,
			expectedErrors: []string{"io.jwt.decode"},
		},
		{
			name: "invalid rand.intn",
			regoCode: `package unifiedpolicy
default allow = false
allow {
    rand.intn(100)
}`,
			expectedErrors: []string{"rand.intn"},
		},
		{
			name: "multiple invalid operations",
			regoCode: `package unifiedpolicy
default allow = false
allow {
    http.send({"method": "GET"})
    io.jwt.decode(input.token)
    rand.intn(100)
}`,
			expectedErrors: []string{"http.send", "io.jwt.decode", "rand.intn"},
		},
		{
			name: "mixed valid and invalid",
			regoCode: `package unifiedpolicy
default allow = false
allow {
    input.evidence.severity != "critical"
    count(input.list) > 0
    http.send({"method": "GET"})
    array.concat(input.list1, input.list2)
}`,
			expectedErrors: []string{"http.send"},
		},
		{
			name: "invalid os.getenv",
			regoCode: `package unifiedpolicy
default allow = false
allow {
    os.getenv("PATH")
}`,
			expectedErrors: []string{"os.getenv"},
		},
		{
			name: "valid array operations",
			regoCode: `package unifiedpolicy
default allow = false
allow {
    array.concat(input.list1, input.list2)
    array.reverse(input.list)
    array.slice(input.list, 0, 5)
}`,
			expectedErrors: []string{},
		},
		{
			name: "valid object operations",
			regoCode: `package unifiedpolicy
default allow = false
allow {
    object.get(input.obj, "key", "default")
    object.keys(input.obj)
    object.union(input.obj1, input.obj2)
}`,
			expectedErrors: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := ast.ParserOptions{
				RegoVersion: ast.RegoV0,
			}
			module, err := ast.ParseModuleWithOpts("test.rego", tt.regoCode, opts)
			if err != nil {
				t.Fatalf("Failed to parse Rego code: %v", err)
			}

			disallowed := unifiedpolicyresource.FindDisallowedOperations(module, allowedOps)

			// Check that we found the expected number of errors
			if len(disallowed) != len(tt.expectedErrors) {
				t.Errorf("Expected %d disallowed operations, got %d: %v", len(tt.expectedErrors), len(disallowed), disallowed)
			}

			// Check that all expected errors are present
			for _, expected := range tt.expectedErrors {
				found := false
				for _, actual := range disallowed {
					if actual == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find disallowed operation %s, but it was not found. Found: %v", expected, disallowed)
				}
			}

			// Check that no unexpected errors are present
			for _, actual := range disallowed {
				found := false
				for _, expected := range tt.expectedErrors {
					if actual == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Found unexpected disallowed operation: %s", actual)
				}
			}
		})
	}
}

// Acceptance tests for Rego validation during plan phase

func TestAccTemplate_invalidRegoSyntax(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	regoPath := acctest.RegoFixturePath(t, "invalid_syntax.rego")
	config := fmt.Sprintf(`
resource "unifiedpolicy_template" "invalid_syntax_test" {
  name             = "Invalid Syntax Test"
  version          = "1.0.0"
  category         = "security"
  data_source_type = "evidence"
  rego             = %q
  parameters       = []
}
`, regoPath)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Invalid Rego Syntax`),
			},
		},
	})
}

func TestAccTemplate_invalidRegoOperations(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	regoPath := acctest.RegoFixturePath(t, "invalid_ops.rego")
	config := fmt.Sprintf(`
resource "unifiedpolicy_template" "invalid_ops_test" {
  name             = "Invalid Operations Test"
  version          = "1.0.0"
  category         = "security"
  data_source_type = "evidence"
  rego             = %q
  parameters       = []
}
`, regoPath)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Disallowed Rego Operations`),
			},
		},
	})
}

func TestAccTemplate_invalidRegoOperationHttpSend(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	regoPath := acctest.RegoFixturePath(t, "invalid_http_send.rego")
	config := fmt.Sprintf(`
resource "unifiedpolicy_template" "invalid_http_send" {
  name             = "Invalid HTTP Send Test"
  version          = "1.0.0"
  category         = "security"
  data_source_type = "evidence"
  rego             = %q
  parameters       = []
}
`, regoPath)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Disallowed Rego Operations`),
			},
		},
	})
}

func TestAccTemplate_invalidRegoOperationIoJwtDecode(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	regoPath := acctest.RegoFixturePath(t, "invalid_jwt_decode.rego")
	config := fmt.Sprintf(`
resource "unifiedpolicy_template" "invalid_jwt_decode" {
  name             = "Invalid JWT Decode Test"
  version          = "1.0.0"
  category         = "security"
  data_source_type = "evidence"
  rego             = %q
  parameters       = []
}
`, regoPath)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Disallowed Rego Operations`),
			},
		},
	})
}

func TestAccTemplate_invalidRegoOperationRandIntn(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	regoPath := acctest.RegoFixturePath(t, "invalid_rand_intn.rego")
	config := fmt.Sprintf(`
resource "unifiedpolicy_template" "invalid_rand_intn" {
  name             = "Invalid Rand Intn Test"
  version          = "1.0.0"
  category         = "security"
  data_source_type = "evidence"
  rego             = %q
  parameters       = []
}
`, regoPath)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Disallowed Rego Operations`),
			},
		},
	})
}

func TestAccTemplate_invalidRegoOperationOsGetenv(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	regoPath := acctest.RegoFixturePath(t, "invalid_os_getenv.rego")
	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "invalid_os_getenv" {
		name             = "Invalid OS Getenv Test"
		version          = "1.0.0"
		category         = "security"
		data_source_type = "evidence"
		rego             = %q
		parameters       = []
	}
	`, regoPath)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Disallowed Rego Operations`),
			},
		},
	})
}

// REMOVED: All policy_config tests - policy_config functionality has been removed
// Only .rego file input is supported now.

// Removed tests:
// - TestAccTemplate_withPolicyConfig
// - TestAccTemplate_withPolicyConfigMinimal
// - TestAccTemplate_policyConfigUpdate
// - TestAccTemplate_policyConfigAndRegoConflict
// - TestAccTemplate_noPolicyDefinition
// - TestAccTemplate_policyConfigImport
// - TestAccTemplate_policyConfigEnforcementModeValidation
// - TestPolicyConfigToRego
// - TestJSONToPolicyConfig

func TestAccTemplate_missingRegoFile(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	config := `
		resource "unifiedpolicy_template" "missing_rego_test" {
			name             = "Missing Rego File Test"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			parameters       = []
		}
	`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`required|rego|Missing Rego|Invalid Request|failed validation`),
			},
		},
	})
}

func TestAccTemplate_invalidRegoFileExtension(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	regoPath := acctest.RegoFixturePath(t, "basic_policy.txt")
	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "invalid_ext_test" {
			name             = "Invalid Extension Test"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, regoPath)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Invalid Rego Path|path must end with .rego`),
			},
		},
	})
}

func TestAccTemplate_nonexistentRegoFile(t *testing.T) {
	acctest.SkipIfNotAcc(t)
	acctest.PreCheck(t)

	regoPath := acctest.RegoFixturePath(t, "nonexistent.rego")
	config := fmt.Sprintf(`
		resource "unifiedpolicy_template" "nonexistent_file_test" {
			name             = "Nonexistent File Test"
			version          = "1.0.0"
			category         = "security"
			data_source_type = "evidence"
			rego             = %q
			parameters       = []
		}
	`, regoPath)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Rego File Not Found|no such file or directory|Rego Error|An error occurred while processing`),
			},
		},
	})
}

// All policy_config tests have been removed - functionality no longer supported

// Helper functions for tests

func mustListValue(ctx context.Context, values []string) types.List {
	elements := make([]types.String, len(values))
	for i, v := range values {
		elements[i] = types.StringValue(v)
	}
	list, diags := types.ListValueFrom(ctx, types.StringType, elements)
	if diags.HasError() {
		panic(diags.Errors()[0].Detail())
	}
	return list
}

func mapsEqual(a, b map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !valueEqual(v, b[k]) {
			return false
		}
	}
	return true
}

func valueEqual(a, b interface{}) bool {
	switch av := a.(type) {
	case []interface{}:
		if bv, ok := b.([]interface{}); ok {
			if len(av) != len(bv) {
				return false
			}
			for i := range av {
				if !valueEqual(av[i], bv[i]) {
					return false
				}
			}
			return true
		}
		return false
	default:
		return a == b
	}
}
