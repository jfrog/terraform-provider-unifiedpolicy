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
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	"github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy"
)

const (
	RulesEndpoint = "unifiedpolicy/api/v1/rules"
	RuleEndpoint  = RulesEndpoint + "/{rule_id}"
)

// RulesListAPIModel is the response shape for GET unifiedpolicy/api/v1/rules (list rules).
type RulesListAPIModel struct {
	Items    []RuleAPIModel `json:"items"`
	Offset   int            `json:"offset"`
	Limit    int            `json:"limit"`
	PageSize int            `json:"page_size"`
}

var _ resource.Resource = &RuleResource{}

func NewRuleResource() resource.Resource {
	return &RuleResource{
		TypeName: "unifiedpolicy_rule",
	}
}

type RuleResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

type RuleResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	IsCustom    types.Bool   `tfsdk:"is_custom"`
	TemplateID  types.String `tfsdk:"template_id"`
	Parameters  types.List   `tfsdk:"parameters"`
}

type RuleParameterModel struct {
	Name  types.String `tfsdk:"name"`
	Value types.String `tfsdk:"value"`
}

type RuleAPIModel struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Description string                  `json:"description,omitempty"`
	IsCustom    bool                    `json:"is_custom,omitempty"` // read-only in API; do not set in Create/Update
	TemplateID  string                  `json:"template_id"`
	Parameters  []RuleParameterAPIModel `json:"parameters"`
	CreatedAt   string                  `json:"created_at,omitempty"`
	CreatedBy   string                  `json:"created_by,omitempty"`
	UpdatedAt   string                  `json:"updated_at,omitempty"`
	UpdatedBy   string                  `json:"updated_by,omitempty"`
}

type RuleParameterAPIModel struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

var ruleParameterObjectType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"name":  types.StringType,
		"value": types.StringType,
	},
}

func (r *RuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

func (r *RuleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Provides a Unified Policy rule resource. This resource allows you to create, update, and delete rules. " +
			"Rules define the specific parameter values for policy evaluation and are based on rule templates.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the rule. This is computed and assigned by the API.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the rule to create. Must be unique.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Free-text description of the rule purpose. Omitted or empty is stored as returned by the API.",
				Optional:    true,
				Computed:    true,
			},
			"is_custom": schema.BoolAttribute{
				Description: "Indicates if the rule is user-defined (true) or predefined (false). This is computed by the API based on how the rule was created.",
				Optional:    true,
				Computed:    true,
			},
			"template_id": schema.StringAttribute{
				Description: "The ID of the template the rule is based on.",
				Required:    true,
			},
			"parameters": schema.ListNestedAttribute{
				Description: "Array of parameter name/value pairs that match the template definition. Optional; defaults to empty if omitted.",
				Optional:    true,
				Computed:    true,
				Default:     listdefault.StaticValue(types.ListValueMust(ruleParameterObjectType, []attr.Value{})),
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Description: "Name of the template parameter.",
							Required:    true,
						},
						"value": schema.StringAttribute{
							Description: "The value assigned to the parameter.",
							Required:    true,
						},
					},
				},
			},
		},
	}
}

func (r *RuleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (m *RuleResourceModel) toAPIModel(ctx context.Context) (RuleAPIModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	apiModel := RuleAPIModel{
		Name:       m.Name.ValueString(),
		TemplateID: m.TemplateID.ValueString(),
	}

	if !m.Description.IsNull() {
		apiModel.Description = m.Description.ValueString()
	}

	// is_custom is read-only per API spec; do not send in Create/Update (omitempty leaves it out)

	// Convert parameters - always send a list, even if empty
	// This ensures consistency with what we read back from the API
	if !m.Parameters.IsNull() {
		var parameters []RuleParameterModel
		d := m.Parameters.ElementsAs(ctx, &parameters, false)
		diags.Append(d...)
		if !diags.HasError() {
			apiParameters := make([]RuleParameterAPIModel, len(parameters))
			for i, p := range parameters {
				apiParameters[i] = RuleParameterAPIModel{
					Name:  p.Name.ValueString(),
					Value: p.Value.ValueString(),
				}
			}
			apiModel.Parameters = apiParameters
		} else {
			// If there's an error, default to empty list
			apiModel.Parameters = []RuleParameterAPIModel{}
		}
	} else {
		// If parameters is null, default to empty list
		apiModel.Parameters = []RuleParameterAPIModel{}
	}

	return apiModel, diags
}

func (r *RuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan RuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiModel, diags := plan.toAPIModel(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var result RuleAPIModel
	httpResponse, err := r.ProviderData.Client.R().
		SetContext(ctx).
		SetBody(apiModel).
		SetResult(&result).
		Post(RulesEndpoint)

	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}

	if httpResponse.IsError() {
		if httpResponse.StatusCode() == http.StatusConflict {
			resp.Diagnostics.AddError(
				"Rule Already Exists",
				fmt.Sprintf("A rule with name '%s' already exists. Please use a different name.", plan.Name.ValueString()),
			)
			return
		}
		// Backend may return 500 with "unique constraint" instead of 409; surface a clear message.
		if httpResponse.StatusCode() == http.StatusInternalServerError &&
			strings.Contains(strings.ToLower(string(httpResponse.Body())), "unique constraint") {
			resp.Diagnostics.AddError(
				"Rule Already Exists",
				fmt.Sprintf("A rule with name '%s' already exists. Please use a different name.", plan.Name.ValueString()),
			)
			return
		}
		errorDiags := unifiedpolicy.HandleAPIError(httpResponse, "create")
		resp.Diagnostics.Append(errorDiags...)
		return
	}

	diags = plan.fromAPIModel(ctx, result)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (m *RuleResourceModel) fromAPIModel(ctx context.Context, api RuleAPIModel) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringValue(api.ID)
	m.Name = types.StringValue(api.Name)
	m.TemplateID = types.StringValue(api.TemplateID)

	// Store description as returned by API; use empty string when API returns "" so config description = "" matches state (no inconsistent result).
	if api.Description != "" {
		m.Description = types.StringValue(api.Description)
	} else {
		m.Description = types.StringValue("")
	}

	// Always set is_custom to match what the API returned
	// This ensures consistency between plan and state
	m.IsCustom = types.BoolValue(api.IsCustom)

	// Convert parameters - always return a list, even if empty
	// This ensures consistency: if user provides empty list [], it stays as empty list
	parameterValues := make([]attr.Value, len(api.Parameters))
	for i, p := range api.Parameters {
		paramObj := types.ObjectValueMust(
			ruleParameterObjectType.AttrTypes,
			map[string]attr.Value{
				"name":  types.StringValue(p.Name),
				"value": types.StringValue(p.Value),
			},
		)
		parameterValues[i] = paramObj
	}
	parametersList, d := types.ListValue(ruleParameterObjectType, parameterValues)
	diags.Append(d...)
	if !diags.HasError() {
		m.Parameters = parametersList
	} else {
		// Fallback to empty list if there's an error creating the list
		m.Parameters = types.ListValueMust(ruleParameterObjectType, []attr.Value{})
	}

	return diags
}

func (r *RuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state RuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var result RuleAPIModel
	httpResponse, err := r.ProviderData.Client.R().
		SetContext(ctx).
		SetPathParam("rule_id", state.ID.ValueString()).
		SetResult(&result).
		Get(RuleEndpoint)

	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, err.Error())
		return
	}

	if httpResponse.StatusCode() == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	if httpResponse.IsError() {
		errorDiags := unifiedpolicy.HandleAPIError(httpResponse, "read")
		resp.Diagnostics.Append(errorDiags...)
		return
	}

	diags := state.fromAPIModel(ctx, result)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *RuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan RuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiModel, diags := plan.toAPIModel(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var result RuleAPIModel
	httpResponse, err := r.ProviderData.Client.R().
		SetContext(ctx).
		SetPathParam("rule_id", plan.ID.ValueString()).
		SetBody(apiModel).
		SetResult(&result).
		Put(RuleEndpoint)

	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}

	if httpResponse.IsError() {
		if httpResponse.StatusCode() == http.StatusConflict {
			resp.Diagnostics.AddError(
				"Rule Name Conflict",
				fmt.Sprintf("A rule with name '%s' already exists. Please use a different name.", plan.Name.ValueString()),
			)
			return
		}
		errorDiags := unifiedpolicy.HandleAPIError(httpResponse, "update")
		resp.Diagnostics.Append(errorDiags...)
		return
	}

	diags = plan.fromAPIModel(ctx, result)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state RuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	httpResponse, err := r.ProviderData.Client.R().
		SetContext(ctx).
		SetPathParam("rule_id", state.ID.ValueString()).
		Delete(RuleEndpoint)

	if err != nil {
		utilfw.UnableToDeleteResourceError(resp, err.Error())
		return
	}

	if httpResponse.StatusCode() != http.StatusNotFound && httpResponse.StatusCode() != http.StatusNoContent {
		if httpResponse.StatusCode() == http.StatusConflict {
			resp.Diagnostics.AddError(
				"Rule In Use",
				"The rule is still referenced by one or more active policies. Remove the rule from all policies before deleting it.",
			)
			return
		}
		errorDiags := unifiedpolicy.HandleAPIError(httpResponse, "delete")
		resp.Diagnostics.Append(errorDiags...)
		return
	}
}

func (r *RuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
