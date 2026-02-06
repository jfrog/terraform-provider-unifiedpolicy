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

package resource

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	"github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy"
	"github.com/open-policy-agent/opa/v1/ast"
)

const (
	TemplatesEndpoint = "unifiedpolicy/api/v1/templates"
	TemplateEndpoint  = TemplatesEndpoint + "/{templateId}"
)

var _ resource.Resource = &TemplateResource{}

func NewTemplateResource() resource.Resource {
	return &TemplateResource{
		TypeName: "unifiedpolicy_template",
	}
}

type TemplateResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

type TemplateResourceModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	Description    types.String `tfsdk:"description"`
	Version        types.String `tfsdk:"version"`
	Category       types.String `tfsdk:"category"`
	DataSourceType types.String `tfsdk:"data_source_type"`
	Parameters     types.List   `tfsdk:"parameters"`
	Rego           types.String `tfsdk:"rego"` // Path to .rego file (or Rego code when reading from API)
	Scanners       types.List   `tfsdk:"scanners"`
	IsCustom       types.Bool   `tfsdk:"is_custom"`
}

type TemplateParameterModel struct {
	Name types.String `tfsdk:"name"`
	Type types.String `tfsdk:"type"`
}

// Template API models (used by this resource and template datasources)
type TemplateAPIModel struct {
	ID             string                      `json:"id,omitempty"`
	Name           string                      `json:"name"`
	Description    *string                     `json:"description,omitempty"`
	Version        string                      `json:"version"`
	Category       string                      `json:"category"`
	DataSourceType string                      `json:"data_source_type"`
	Parameters     []TemplateParameterAPIModel `json:"parameters,omitempty"`
	Rego           string                      `json:"rego"`
	Scanners       []string                    `json:"scanners,omitempty"`
	IsCustom       bool                        `json:"is_custom"`
	CreatedAt      string                      `json:"created_at,omitempty"`
	CreatedBy      string                      `json:"created_by,omitempty"`
	UpdatedAt      string                      `json:"updated_at,omitempty"`
	UpdatedBy      string                      `json:"updated_by,omitempty"`
}

type TemplateParameterAPIModel struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type TemplatesListAPIModel struct {
	Items    []TemplateAPIModel `json:"items"`
	Offset   int                `json:"offset"`
	Limit    int                `json:"limit"`
	PageSize int                `json:"page_size"`
}

// regoContentFromFile reads Rego code from a .rego file. The path must be an absolute (full) path
// and must end with ".rego". Returns the file content or an error if the path is invalid or the file cannot be read.
func regoContentFromFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", &regoPathError{path: path, reason: "path cannot be empty"}
	}
	if !filepath.IsAbs(path) {
		return "", &regoPathError{path: path, reason: "path must be an absolute (full) path"}
	}
	if !strings.HasSuffix(path, ".rego") {
		return "", &regoPathError{path: path, reason: "path must end with .rego"}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// regoPathError is returned when the rego path is invalid (e.g. not absolute, wrong extension).
type regoPathError struct {
	path   string
	reason string
}

func (e *regoPathError) Error() string {
	return e.reason + ": " + e.path
}

// regoContentValidator validates that the rego attribute is the full (absolute) path to a .rego file and that its content is valid.
type regoContentValidator struct{}

// Description returns a plain text description of the validator.
func (v regoContentValidator) Description(ctx context.Context) string {
	return "Validates that rego is the full (absolute) path to a .rego file and that the Rego code is valid and uses only allowed operations"
}

// MarkdownDescription returns a markdown formatted description of the validator.
func (v regoContentValidator) MarkdownDescription(ctx context.Context) string {
	return "Validates that rego is the full (absolute) path to a .rego file and that the Rego code is valid and uses only allowed operations"
}

// ValidateString performs the validation.
func (v regoContentValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	// If the value is unknown or null, skip validation
	if req.ConfigValue.IsUnknown() || req.ConfigValue.IsNull() {
		return
	}

	regoPath := req.ConfigValue.ValueString()
	regoCode, err := regoContentFromFile(regoPath)
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Rego Error",
			"An error occurred while processing the rego file: "+err.Error(),
		)
		return
	}

	if regoCode == "" {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Empty Rego",
			"The rego path was provided but no content was found.",
		)
		return
	}

	const maxRegoChars = 65536
	if len(regoCode) > maxRegoChars {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Rego Code Too Long",
			"The Rego code must be 1-65536 characters. Current length: "+strconv.Itoa(len(regoCode))+". Please shorten the policy or split into multiple modules.",
		)
		return
	}

	// Validate Rego syntax
	opts := ast.ParserOptions{
		RegoVersion: ast.RegoV0,
	}
	module, err := ast.ParseModuleWithOpts("policy.rego", regoCode, opts)
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Rego Syntax",
			"The Rego code contains syntax errors. "+err.Error()+"\n\n"+
				"Please check your Rego code for:\n"+
				"- Missing or mismatched brackets, braces, or parentheses\n"+
				"- Incorrect package declarations\n"+
				"- Invalid rule definitions\n"+
				"- Syntax errors in expressions",
		)
		return
	}

	// Validate that only allowed operations are used
	allowedOps := GetAllowedRegoOperations()
	disallowedOps := FindDisallowedOperations(module, allowedOps)
	if len(disallowedOps) > 0 {
		opsList := ""
		for i, op := range disallowedOps {
			if i > 0 {
				opsList += ", "
			}
			opsList += op
		}
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Disallowed Rego Operations",
			"The Rego code uses operations that are not allowed: "+opsList+"\n\n"+
				"Only specific built-in OPA functions are allowed for policy evaluation.\n"+
				"Please refer to the List of Valid Rego Operations documentation for allowed functions.",
		)
		return
	}
}

// GetAllowedRegoOperations returns the set of allowed Rego operations
// This function is exported for testing purposes
func GetAllowedRegoOperations() map[string]bool {
	allowed := make(map[string]bool)

	// Comparison operators
	for _, op := range []string{"eq", "equal", "neq", "gt", "lt", "gte", "lte"} {
		allowed[op] = true
	}

	// Arithmetic operations
	for _, op := range []string{"plus", "minus", "mul", "div", "abs", "round", "ceil", "floor"} {
		allowed[op] = true
	}

	// String operations
	for _, op := range []string{"concat", "contains", "endswith", "format_int", "indexof", "lower", "replace", "split", "startswith", "substring", "trim", "trim_left", "trim_prefix", "trim_right", "trim_suffix", "upper"} {
		allowed[op] = true
	}

	// Array operations
	for _, op := range []string{"array.concat", "array.reverse", "array.slice"} {
		allowed[op] = true
	}

	// Set operations
	for _, op := range []string{"set_diff", "intersection", "union"} {
		allowed[op] = true
	}

	// Object operations
	for _, op := range []string{"object.get", "object.keys", "object.remove", "object.union", "object.union_n"} {
		allowed[op] = true
	}

	// Type conversion
	allowed["to_number"] = true

	// Aggregation
	for _, op := range []string{"count", "sum", "max", "min", "sort", "all", "any"} {
		allowed[op] = true
	}

	// Logic operations
	for _, op := range []string{"and", "or"} {
		allowed[op] = true
	}

	// JSON operations
	for _, op := range []string{"json.filter", "json.patch", "json.remove", "json.unmarshal"} {
		allowed[op] = true
	}

	// Encoding
	for _, op := range []string{"base64.encode", "base64.decode", "base64url.encode", "base64url.decode", "urlquery.encode", "urlquery.decode"} {
		allowed[op] = true
	}

	// Time operations
	for _, op := range []string{"time.now_ns", "time.parse_ns", "time.parse_rfc3339_ns", "time.parse_duration_ns"} {
		allowed[op] = true
	}

	// Units
	for _, op := range []string{"units.parse", "units.parse_bytes"} {
		allowed[op] = true
	}

	// Regex
	for _, op := range []string{"regex.match", "regex.find_all_string_submatch_n", "regex.split"} {
		allowed[op] = true
	}

	// Glob matching
	allowed["glob.match"] = true

	// Graph
	for _, op := range []string{"graph.reachable", "graph.reachable_paths"} {
		allowed[op] = true
	}

	// Type checking
	for _, op := range []string{"is_number", "is_string", "is_boolean", "is_array", "is_object", "is_set", "is_null"} {
		allowed[op] = true
	}

	// Type name
	allowed["type_name"] = true

	return allowed
}

// FindDisallowedOperations walks the AST and finds any function calls that are not in the allowed list
// This function is exported for testing purposes
func FindDisallowedOperations(module *ast.Module, allowedOps map[string]bool) []string {
	var disallowed []string
	seen := make(map[string]bool)

	// Visitor to find all function calls
	// In Rego AST, function calls are represented as *ast.Expr where the operator is a Ref
	visitor := ast.NewGenericVisitor(func(x interface{}) bool {
		switch node := x.(type) {
		case *ast.Expr:
			// Check if this is a function call (has an operator that's a Ref)
			if node.IsCall() {
				ref := node.Operator()
				// Build the function name from the ref
				parts := make([]string, 0, len(ref))
				for _, term := range ref {
					switch v := term.Value.(type) {
					case ast.String:
						parts = append(parts, string(v))
					case ast.Var:
						parts = append(parts, string(v))
					}
				}

				if len(parts) > 0 {
					// Build the full function name by joining all parts with "."
					// e.g., "io.jwt.decode", "http.send", "array.concat", "count"
					funcName := parts[0]
					for i := 1; i < len(parts); i++ {
						funcName += "." + parts[i]
					}

					// Check if the full name is allowed
					if !allowedOps[funcName] {
						// Also check the short name (last part) for some functions
						// e.g., "decode" for "io.jwt.decode" (though this is unlikely to be allowed)
						shortName := parts[len(parts)-1]
						if !allowedOps[shortName] {
							if !seen[funcName] {
								disallowed = append(disallowed, funcName)
								seen[funcName] = true
							}
						}
					}
				}
			}
		}
		return false
	})

	visitor.Walk(module)

	return disallowed
}

func (r *TemplateResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

func (r *TemplateResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Provides a Unified Policy template resource. This resource allows you to create, update, and delete templates. " +
			"Templates define reusable logic (business rules) for policies using Rego policy language code from a .rego file.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the template. This is computed and assigned by the API.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The template name. Must be unique. 1-255 characters.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 255),
				},
			},
			"description": schema.StringAttribute{
				Description: "A free-text description of the template. This field is optional. Up to 2048 characters.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(2048),
				},
			},
			"version": schema.StringAttribute{
				Description: "The template version. 1-100 characters.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 100),
				},
			},
			"category": schema.StringAttribute{
				Description: "Template category. Must be one of: security, legal, operational, quality, audit, workflow.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("security", "legal", "operational", "quality", "audit", "workflow"),
				},
			},
			"data_source_type": schema.StringAttribute{
				Description: "The type of data source the template expects. For creation only 'noop' and 'evidence' are allowed; 'xray' may appear when reading system templates.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("noop", "evidence", "xray"),
				},
			},
			"parameters": schema.ListNestedAttribute{
				Description: "List of configurable parameters for the template. Optional; defaults to an empty list. Maximum 20 parameters allowed.",
				Optional:    true,
				Computed:    true,
				Default: listdefault.StaticValue(
					types.ListValueMust(
						types.ObjectType{AttrTypes: map[string]attr.Type{"name": types.StringType, "type": types.StringType}},
						[]attr.Value{},
					),
				),
				Validators: []validator.List{
					listvalidator.SizeAtMost(20),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Description: "Parameter name. Must begin and end with an alphanumeric character and may consist only of dashes, underscores, dots and alphanumerics in between.",
							Required:    true,
							Validators: []validator.String{
								stringvalidator.LengthBetween(1, 100),
								stringvalidator.RegexMatches(
									regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$`),
									"Parameter name must begin and end with alphanumeric characters",
								),
							},
						},
						"type": schema.StringAttribute{
							Description: "Parameter type. Must be one of: string, bool, int, float, object.",
							Required:    true,
							Validators: []validator.String{
								stringvalidator.OneOf("string", "bool", "int", "float", "object"),
							},
						},
					},
				},
			},
			"rego": schema.StringAttribute{
				Description: "Full (absolute) path to a .rego file (e.g. `rego = \"/path/to/policies/security_vulnerability.rego\"`). " +
					"The file is read, validated (syntax and allowed operations), and its content is sent to the API. " +
					"Only absolute paths to .rego files are accepted; relative paths and inline content are not supported. " +
					"The path is stored in state; the API stores and returns the Rego code content. Required for create and update.",
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					regoContentValidator{},
				},
			},
			"scanners": schema.ListAttribute{
				Description: "List of scanner types that this template supports. Optional. Defaults to empty list []. Allowed values: secrets, sca, exposures, contextual_analysis, malicious_package.",
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Default: listdefault.StaticValue(
					types.ListValueMust(types.StringType, []attr.Value{}),
				),
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.OneOf("secrets", "sca", "exposures", "contextual_analysis", "malicious_package"),
					),
				},
			},
			"is_custom": schema.BoolAttribute{
				Description: "Indicates whether this is a custom template (created by user) or a system template.",
				Computed:    true,
			},
		},
	}
}

func (r *TemplateResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (m *TemplateResourceModel) toAPIModel(ctx context.Context) (TemplateAPIModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	apiModel := TemplateAPIModel{
		Name:           m.Name.ValueString(),
		Version:        m.Version.ValueString(),
		Category:       m.Category.ValueString(),
		DataSourceType: m.DataSourceType.ValueString(),
	}

	// Rego: read content from .rego file path
	if !m.Rego.IsNull() {
		content, err := regoContentFromFile(m.Rego.ValueString())
		if err != nil {
			var pathErr *regoPathError
			if errors.As(err, &pathErr) {
				diags.AddError("Invalid Rego Path", "The rego field must be the full (absolute) path to a .rego file. "+err.Error())
			} else {
				diags.AddError("Rego File Not Found", "Cannot read Rego file: "+m.Rego.ValueString()+". "+err.Error())
			}
			return apiModel, diags
		}
		apiModel.Rego = content
	}

	// Handle description: if provided (even as empty string), set it; if null, leave as nil
	if !m.Description.IsNull() {
		descValue := m.Description.ValueString()
		apiModel.Description = &descValue
	}
	// If Description is null, apiModel.Description remains nil (not set), which will be omitted from JSON

	if !m.Parameters.IsNull() {
		var params []TemplateParameterModel
		d := m.Parameters.ElementsAs(ctx, &params, false)
		diags.Append(d...)
		if !diags.HasError() {
			apiParams := make([]TemplateParameterAPIModel, len(params))
			for i, param := range params {
				apiParams[i] = TemplateParameterAPIModel{
					Name: param.Name.ValueString(),
					Type: param.Type.ValueString(),
				}
			}
			apiModel.Parameters = apiParams
		}
	}
	// When Parameters is null or not set, leave apiModel.Parameters as nil so omitempty omits it from JSON; API defaults to []

	if !m.Scanners.IsNull() {
		var scanners []string
		d := m.Scanners.ElementsAs(ctx, &scanners, false)
		diags.Append(d...)
		if !diags.HasError() {
			apiModel.Scanners = scanners
		}
	}

	return apiModel, diags
}

func (r *TemplateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan TemplateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Rego.IsNull() || plan.Rego.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing Rego",
			"The 'rego' field is required and must be the full (absolute) path to a .rego file.",
		)
		return
	}

	tflog.Info(ctx, "Creating template", map[string]interface{}{
		"name": plan.Name.ValueString(),
	})

	apiModel, diags := plan.toAPIModel(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var result TemplateAPIModel
	httpResponse, err := r.ProviderData.Client.R().
		SetContext(ctx).
		SetBody(apiModel).
		SetResult(&result).
		Post(TemplatesEndpoint)

	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}

	if httpResponse.IsError() {
		errorDiags := unifiedpolicy.HandleAPIErrorWithType(httpResponse, "create", "template")
		resp.Diagnostics.Append(errorDiags...)
		return
	}

	regoPath := plan.Rego.ValueString()
	diags = plan.fromAPIModel(ctx, result)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.Rego = types.StringValue(regoPath)

	tflog.Info(ctx, "Template created successfully", map[string]interface{}{
		"id":   plan.ID.ValueString(),
		"name": plan.Name.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (m *TemplateResourceModel) fromAPIModel(ctx context.Context, apiModel TemplateAPIModel) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringValue(apiModel.ID)
	m.Name = types.StringValue(apiModel.Name)
	m.Category = types.StringValue(apiModel.Category)
	m.DataSourceType = types.StringValue(apiModel.DataSourceType)

	// Store Rego code from API response
	// Note: When reading from API, we get Rego code, not a file path
	// The code is stored directly (file path validation only applies during create/update)
	m.Rego = types.StringValue(apiModel.Rego)

	// Set version from API response
	m.Version = types.StringValue(apiModel.Version)

	// Handle description: if pointer is nil, set to null; otherwise use the value (even if empty string)
	if apiModel.Description != nil {
		m.Description = types.StringValue(*apiModel.Description)
	} else {
		m.Description = types.StringNull()
	}

	paramAttrTypes := map[string]attr.Type{
		"name": types.StringType,
		"type": types.StringType,
	}
	if len(apiModel.Parameters) > 0 {
		parameters := make([]types.Object, len(apiModel.Parameters))
		for i, param := range apiModel.Parameters {
			paramAttrs := map[string]attr.Value{
				"name": types.StringValue(param.Name),
				"type": types.StringValue(param.Type),
			}
			paramObj, paramDiags := types.ObjectValue(paramAttrTypes, paramAttrs)
			diags.Append(paramDiags...)
			if !diags.HasError() {
				parameters[i] = paramObj
			}
		}
		parametersList, paramListDiags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: paramAttrTypes}, parameters)
		diags.Append(paramListDiags...)
		if !diags.HasError() {
			m.Parameters = parametersList
		} else {
			m.Parameters = types.ListValueMust(types.ObjectType{AttrTypes: paramAttrTypes}, []attr.Value{})
		}
	} else {
		m.Parameters = types.ListValueMust(types.ObjectType{AttrTypes: paramAttrTypes}, []attr.Value{})
	}

	// Convert scanners - always return empty list if API doesn't return them (since we have a default)
	if len(apiModel.Scanners) > 0 {
		scanners := make([]types.String, len(apiModel.Scanners))
		for i, scanner := range apiModel.Scanners {
			scanners[i] = types.StringValue(scanner)
		}
		scannersList, scannerDiags := types.ListValueFrom(ctx, types.StringType, scanners)
		diags.Append(scannerDiags...)
		if !diags.HasError() {
			m.Scanners = scannersList
		} else {
			// Fallback to empty list if there's an error (to match default)
			m.Scanners = types.ListValueMust(types.StringType, []attr.Value{})
		}
	} else {
		// If API doesn't return scanners, default to empty list (to match schema default)
		m.Scanners = types.ListValueMust(types.StringType, []attr.Value{})
	}

	// Set is_custom
	m.IsCustom = types.BoolValue(apiModel.IsCustom)

	return diags
}

func (r *TemplateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state TemplateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading template", map[string]interface{}{
		"id": state.ID.ValueString(),
	})

	var result TemplateAPIModel
	httpResponse, err := r.ProviderData.Client.R().
		SetContext(ctx).
		SetPathParam("templateId", state.ID.ValueString()).
		SetResult(&result).
		Get(TemplateEndpoint)

	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, err.Error())
		return
	}

	if httpResponse.StatusCode() == http.StatusNotFound {
		tflog.Warn(ctx, "Template not found, removing from state", map[string]interface{}{
			"id": state.ID.ValueString(),
		})
		resp.State.RemoveResource(ctx)
		return
	}

	if httpResponse.IsError() {
		errorDiags := unifiedpolicy.HandleAPIErrorWithType(httpResponse, "read", "template")
		resp.Diagnostics.Append(errorDiags...)
		return
	}

	regoPath := state.Rego.ValueString()
	diags := state.fromAPIModel(ctx, result)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Rego = types.StringValue(regoPath)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *TemplateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan TemplateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Rego.IsNull() || plan.Rego.ValueString() == "" {
		resp.Diagnostics.AddError(
			"Missing Rego",
			"The 'rego' field must be the full (absolute) path to a .rego file.",
		)
		return
	}

	tflog.Info(ctx, "Updating template", map[string]interface{}{
		"id": plan.ID.ValueString(),
	})

	apiModel, diags := plan.toAPIModel(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var result TemplateAPIModel
	httpResponse, err := r.ProviderData.Client.R().
		SetContext(ctx).
		SetPathParam("templateId", plan.ID.ValueString()).
		SetBody(apiModel).
		SetResult(&result).
		Put(TemplateEndpoint)

	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}

	if httpResponse.IsError() {
		errorDiags := unifiedpolicy.HandleAPIErrorWithType(httpResponse, "update", "template")
		resp.Diagnostics.Append(errorDiags...)
		return
	}

	regoPath := plan.Rego.ValueString()
	diags = plan.fromAPIModel(ctx, result)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.Rego = types.StringValue(regoPath)

	tflog.Info(ctx, "Template updated successfully", map[string]interface{}{
		"id": plan.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TemplateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state TemplateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Deleting template", map[string]interface{}{
		"id": state.ID.ValueString(),
	})

	httpResponse, err := r.ProviderData.Client.R().
		SetContext(ctx).
		SetPathParam("templateId", state.ID.ValueString()).
		Delete(TemplateEndpoint)

	if err != nil {
		utilfw.UnableToDeleteResourceError(resp, err.Error())
		return
	}

	if httpResponse.StatusCode() != http.StatusNotFound && httpResponse.StatusCode() != http.StatusNoContent {
		errorDiags := unifiedpolicy.HandleAPIErrorWithType(httpResponse, "delete", "template")
		resp.Diagnostics.Append(errorDiags...)
		return
	}

	if httpResponse.StatusCode() == http.StatusNotFound {
		tflog.Warn(ctx, "Template not found during deletion, assuming already deleted", map[string]interface{}{
			"id": state.ID.ValueString(),
		})
		return
	}

	tflog.Info(ctx, "Template deleted successfully", map[string]interface{}{
		"id": state.ID.ValueString(),
	})
}

func (r *TemplateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
