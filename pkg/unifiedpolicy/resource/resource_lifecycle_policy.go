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
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	"github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy"
)

// Lifecycle policy API endpoints (used by this resource and lifecycle policy datasources)
const (
	PoliciesEndpoint = "unifiedpolicy/api/v1/policies"
	PolicyEndpoint   = PoliciesEndpoint + "/{policyId}"
)

type LifecyclePolicyResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

type LifecyclePolicyResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Mode        types.String `tfsdk:"mode"`
	Action      types.Object `tfsdk:"action"`
	Scope       types.Object `tfsdk:"scope"`
	RuleIDs     types.List   `tfsdk:"rule_ids"`
}

type LifecycleActionModel struct {
	Type  types.String `tfsdk:"type"`
	Stage types.Object `tfsdk:"stage"`
}

type LifecycleStageModel struct {
	Key  types.String `tfsdk:"key"`
	Gate types.String `tfsdk:"gate"`
}

type LifecycleScopeModel struct {
	Type              types.String `tfsdk:"type"`
	ProjectKeys       types.List   `tfsdk:"project_keys"`
	ApplicationKeys   types.List   `tfsdk:"application_keys"`
	ApplicationLabels types.List   `tfsdk:"application_labels"`
}

type ApplicationLabelModel struct {
	Key   types.String `tfsdk:"key"`
	Value types.String `tfsdk:"value"`
}

type LifecyclePolicyAPIModel struct {
	ID          string           `json:"id,omitempty"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Enabled     bool             `json:"enabled"`
	Mode        string           `json:"mode"`
	Action      *LifecycleAction `json:"action"`
	Scope       *LifecycleScope  `json:"scope"`
	RuleIDs     []string         `json:"rule_ids,omitempty"`
	CreatedAt   string           `json:"created_at,omitempty"`
	CreatedBy   string           `json:"created_by,omitempty"`
	UpdatedAt   string           `json:"updated_at,omitempty"`
	UpdatedBy   string           `json:"updated_by,omitempty"`
}

type LifecycleAction struct {
	Type  string          `json:"type"`
	Stage *LifecycleStage `json:"stage"`
}

type LifecycleStage struct {
	Key  string `json:"key"`
	Gate string `json:"gate"`
}

type LifecycleScope struct {
	Type              string             `json:"type"`
	ProjectKeys       []string           `json:"project_keys,omitempty"`
	ApplicationKeys   []string           `json:"application_keys,omitempty"`
	ApplicationLabels []ApplicationLabel `json:"application_labels,omitempty"`
}

type ApplicationLabel struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

var _ resource.Resource = &LifecyclePolicyResource{}

func NewLifecyclePolicyResource() resource.Resource {
	return &LifecyclePolicyResource{
		TypeName: "unifiedpolicy_lifecycle_policy",
	}
}

func (r *LifecyclePolicyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

func (r *LifecyclePolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Provides a Unified Policy lifecycle policy resource. This resource allows you to create, update, and delete lifecycle policies. " +
			"Lifecycle policies define enforcement mode, lifecycle actions (stage/gate), scope (project or application), and the rules to apply.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the lifecycle policy. This is computed and assigned by the API.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The policy name. Must be unique.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "A free-text description of the policy. This field is optional.",
				Optional:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the policy is active. Set to true to enable the policy, false to disable it.",
				Required:    true,
			},
			"mode": schema.StringAttribute{
				Description: "Enforcement mode. Must be either 'block' or 'warning'. " +
					"'block' will prevent promotion when rules are violated. " +
					"'warning' will allow promotion but log violations.",
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf("block", "warning"),
				},
			},
			"rule_ids": schema.ListAttribute{
				Description: "IDs of rules enforced by this policy. " +
					"The API allows exactly one rule per policy (documentation describes an array but validation enforces maximum 1 item). " +
					"The rule ID must reference a valid rule that exists in the system.",
				ElementType: types.StringType,
				Required:    true,
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.SizeAtMost(1),
					listvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
			},
		},
		Blocks: map[string]schema.Block{
			"action": schema.SingleNestedBlock{
				Description: "Lifecycle action governed by the policy.",
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						Description: "Action type. Currently supports 'certify_to_gate'.",
						Required:    true,
						Validators: []validator.String{
							stringvalidator.OneOf("certify_to_gate"),
						},
					},
				},
				Blocks: map[string]schema.Block{
					"stage": schema.SingleNestedBlock{
						Description: "Lifecycle stage and gate configuration.",
						Attributes: map[string]schema.Attribute{
							"key": schema.StringAttribute{
								Description: "Lifecycle stage key (e.g., 'qa', 'production').",
								Required:    true,
							},
							"gate": schema.StringAttribute{
								Description: "Lifecycle gate. Must be one of: 'entry', 'exit', 'release'.",
								Required:    true,
								Validators: []validator.String{
									stringvalidator.OneOf("entry", "exit", "release"),
								},
							},
						},
					},
				},
			},
			"scope": schema.SingleNestedBlock{
				Description: "Where the policy applies (project-level or application-level).",
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						Description: "Scope type. Must be either 'project' or 'application'.",
						Required:    true,
						Validators: []validator.String{
							stringvalidator.OneOf("project", "application"),
						},
					},
					"project_keys": schema.ListAttribute{
						Description: "Projects to include (required for project scope). " +
							"The API requires exactly one project key. Each key must be at least 1 character.",
						ElementType: types.StringType,
						Optional:    true,
						Validators: []validator.List{
							listvalidator.SizeAtMost(1),
							listvalidator.ValueStringsAre(
								stringvalidator.LengthAtLeast(1),
							),
						},
					},
					"application_keys": schema.ListAttribute{
						Description: "Applications to include (used with application scope). " +
							"Each application key must be at least 1 character in length.",
						ElementType: types.StringType,
						Optional:    true,
						Validators: []validator.List{
							listvalidator.ValueStringsAre(
								stringvalidator.LengthAtLeast(1),
							),
						},
					},
				},
				Blocks: map[string]schema.Block{
					"application_labels": schema.ListNestedBlock{
						Description: "Label filters for application scope. Each entry has key and value.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"key": schema.StringAttribute{
									Description: "Label key.",
									Required:    true,
								},
								"value": schema.StringAttribute{
									Description: "Label value.",
									Required:    true,
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *LifecyclePolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

// toAPIModel converts the Terraform resource model to the API request model.
func (m *LifecyclePolicyResourceModel) toAPIModel(ctx context.Context) (LifecyclePolicyAPIModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	// API requires these on Create and Update (full body); validate before sending
	if m.Action.IsNull() || m.Action.IsUnknown() {
		diags.AddError(
			"Missing Required Field",
			"action is required. The API requires an action block with type and stage (key and gate).",
		)
		return LifecyclePolicyAPIModel{}, diags
	}
	if m.Scope.IsNull() || m.Scope.IsUnknown() {
		diags.AddError(
			"Missing Required Field",
			"scope is required. The API requires a scope block with type and project_keys or application_keys/application_labels.",
		)
		return LifecyclePolicyAPIModel{}, diags
	}

	apiModel := LifecyclePolicyAPIModel{
		Name:    m.Name.ValueString(),
		Enabled: m.Enabled.ValueBool(),
		Mode:    m.Mode.ValueString(),
	}

	if !m.Description.IsNull() && !m.Description.IsUnknown() {
		descriptionValue := m.Description.ValueString()
		// Only include description if it's not empty (empty string should be treated as null/omitted)
		if descriptionValue != "" {
			apiModel.Description = descriptionValue
		}
		// If description is empty string, don't include it in the request (treat as null)
	}

	// Convert action (already validated as non-null above)
	{
		actionAttrs := m.Action.Attributes()

		// Extract type
		typeValue := types.StringNull()
		if typeAttr, ok := actionAttrs["type"]; ok {
			if tv, ok := typeAttr.(types.String); ok {
				typeValue = tv
			}
		}

		apiModel.Action = &LifecycleAction{
			Type: typeValue.ValueString(),
		}

		// Extract stage (nested block) - Required by API when action is present
		stageAttr, stageExists := actionAttrs["stage"]
		if !stageExists || stageAttr.IsNull() {
			diags.AddError(
				"Missing Required Field",
				"action.stage is required when action is specified. Both stage.key and stage.gate must be provided.",
			)
			return apiModel, diags
		}

		stageObj, ok := stageAttr.(types.Object)
		if !ok {
			diags.AddError(
				"Invalid Stage Configuration",
				"action.stage must be an object with 'key' and 'gate' attributes.",
			)
			return apiModel, diags
		}

		stageAttrs := stageObj.Attributes()
		keyValue := types.StringNull()
		gateValue := types.StringNull()

		if keyAttr, ok := stageAttrs["key"]; ok {
			if kv, ok := keyAttr.(types.String); ok {
				keyValue = kv
			}
		}
		if gateAttr, ok := stageAttrs["gate"]; ok {
			if gv, ok := gateAttr.(types.String); ok {
				gateValue = gv
			}
		}

		// Validate that both key and gate are provided (required by API)
		if keyValue.IsNull() || gateValue.IsNull() {
			diags.AddError(
				"Missing Required Stage Fields",
				"action.stage.key and action.stage.gate are both required when action is specified.",
			)
			return apiModel, diags
		}

		apiModel.Action.Stage = &LifecycleStage{
			Key:  keyValue.ValueString(),
			Gate: gateValue.ValueString(),
		}
	}

	// Convert scope
	if !m.Scope.IsNull() {
		scopeAttrs := m.Scope.Attributes()

		// Extract type
		typeValue := types.StringNull()
		if typeAttr, ok := scopeAttrs["type"]; ok {
			if tv, ok := typeAttr.(types.String); ok {
				typeValue = tv
			}
		}

		if typeValue.IsNull() {
			diags.AddError("Missing Scope Type", "Scope type is required")
			return apiModel, diags
		}

		scopeType := typeValue.ValueString()
		apiModel.Scope = &LifecycleScope{
			Type: scopeType,
		}

		// Convert project_keys
		var hasProjectKeys bool
		if projectKeysAttr, ok := scopeAttrs["project_keys"]; ok && !projectKeysAttr.IsNull() {
			if projectKeysList, ok := projectKeysAttr.(types.List); ok {
				var projectKeys []string
				diags.Append(projectKeysList.ElementsAs(ctx, &projectKeys, false)...)
				if !diags.HasError() && len(projectKeys) > 0 {
					apiModel.Scope.ProjectKeys = projectKeys
					hasProjectKeys = true
				}
			}
		}

		// Convert application_keys
		var hasApplicationKeys bool
		if applicationKeysAttr, ok := scopeAttrs["application_keys"]; ok && !applicationKeysAttr.IsNull() {
			if applicationKeysList, ok := applicationKeysAttr.(types.List); ok {
				var applicationKeys []string
				diags.Append(applicationKeysList.ElementsAs(ctx, &applicationKeys, false)...)
				if !diags.HasError() && len(applicationKeys) > 0 {
					apiModel.Scope.ApplicationKeys = applicationKeys
					hasApplicationKeys = true
				}
			}
		}

		// Convert application_labels
		if labelsAttr, ok := scopeAttrs["application_labels"]; ok && !labelsAttr.IsNull() {
			if labelsList, ok := labelsAttr.(types.List); ok {
				// Manually extract each label object from the list
				elements := labelsList.Elements()
				apiLabels := make([]ApplicationLabel, 0, len(elements))
				for _, elem := range elements {
					if labelObj, ok := elem.(types.Object); ok {
						labelAttrs := labelObj.Attributes()
						keyValue := types.StringNull()
						valueValue := types.StringNull()

						if keyAttr, ok := labelAttrs["key"]; ok {
							if kv, ok := keyAttr.(types.String); ok {
								keyValue = kv
							}
						}
						if valueAttr, ok := labelAttrs["value"]; ok {
							if vv, ok := valueAttr.(types.String); ok {
								valueValue = vv
							}
						}

						if !keyValue.IsNull() && !valueValue.IsNull() {
							apiLabels = append(apiLabels, ApplicationLabel{
								Key:   keyValue.ValueString(),
								Value: valueValue.ValueString(),
							})
						}
					}
				}
				if len(apiLabels) > 0 {
					apiModel.Scope.ApplicationLabels = apiLabels
				}
			}
		}

		// Validate scope requirements per API: project scope requires exactly one project key; application scope may use application_keys and/or application_labels
		if scopeType == "project" && !hasProjectKeys {
			diags.AddError(
				"Invalid Scope Configuration",
				"Scope type 'project' requires project_keys with exactly one project key.",
			)
			return apiModel, diags
		}
		if scopeType == "project" && hasProjectKeys && len(apiModel.Scope.ProjectKeys) != 1 {
			diags.AddError(
				"Invalid Scope Configuration",
				"project_keys must contain exactly one project key (API validation).",
			)
			return apiModel, diags
		}
		if scopeType == "application" && !hasApplicationKeys && len(apiModel.Scope.ApplicationLabels) == 0 {
			diags.AddError(
				"Invalid Scope Configuration",
				"Scope type 'application' requires application_keys and/or application_labels.",
			)
			return apiModel, diags
		}
	}

	// Convert rule_ids (required field per API spec)
	if m.RuleIDs.IsNull() || m.RuleIDs.IsUnknown() {
		diags.AddError(
			"Missing Required Field",
			"rule_ids is required and must contain at least one rule ID.",
		)
		return apiModel, diags
	}

	var ruleIDs []string
	diags.Append(m.RuleIDs.ElementsAs(ctx, &ruleIDs, false)...)
	if diags.HasError() {
		return apiModel, diags
	}

	// Validate: API requires at least one and at most one rule ID per policy
	if len(ruleIDs) == 0 {
		diags.AddError(
			"Invalid Rule IDs",
			"rule_ids must contain at least one rule ID.",
		)
		return apiModel, diags
	}
	if len(ruleIDs) > 1 {
		diags.AddError(
			"Invalid Rule IDs",
			"rule_ids must contain maximum 1 item (API allows only one rule per policy).",
		)
		return apiModel, diags
	}

	apiModel.RuleIDs = ruleIDs

	return apiModel, diags
}

func (r *LifecyclePolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan LifecyclePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiModel, diags := plan.toAPIModel(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Log the API model for debugging
	apiModelJSON, _ := json.Marshal(apiModel)
	tflog.Debug(ctx, "API request details", map[string]interface{}{
		"endpoint": PoliciesEndpoint,
		"method":   "POST",
		"name":     plan.Name.ValueString(),
		"body":     string(apiModelJSON),
	})

	var apiResponse LifecyclePolicyAPIModel
	httpResponse, err := r.ProviderData.Client.R().
		SetContext(ctx).
		SetBody(apiModel).
		SetResult(&apiResponse).
		Post(PoliciesEndpoint)

	if err != nil {
		tflog.Error(ctx, "Failed to send create request", map[string]interface{}{
			"name":  plan.Name.ValueString(),
			"error": err.Error(),
		})
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}

	// API returns 201 Created on success
	if httpResponse.StatusCode() != http.StatusCreated {
		if httpResponse.StatusCode() == http.StatusConflict {
			tflog.Warn(ctx, "Policy already exists", map[string]interface{}{
				"name": plan.Name.ValueString(),
			})
			resp.Diagnostics.AddError(
				"Policy Already Exists",
				fmt.Sprintf("A policy with name '%s' already exists. Please use a different name.", plan.Name.ValueString()),
			)
			return
		}
		// Log full response for debugging
		responseBody := string(httpResponse.Body())
		tflog.Error(ctx, "API returned error during create", map[string]interface{}{
			"name":        plan.Name.ValueString(),
			"status_code": httpResponse.StatusCode(),
			"response":    responseBody,
			"request":     string(apiModelJSON),
		})
		errorDiags := unifiedpolicy.HandleAPIError(httpResponse, "create")
		resp.Diagnostics.Append(errorDiags...)
		return
	}

	tflog.Debug(ctx, "API create response received", map[string]interface{}{
		"id":          apiResponse.ID,
		"status_code": httpResponse.StatusCode(),
	})

	diags = plan.fromAPIModel(ctx, apiResponse, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Ensure ID is set
	plan.ID = types.StringValue(apiResponse.ID)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// fromAPIModel converts the API response model to the Terraform resource model.
// labelsFallback: when the API does not return application_labels (known limitation), use this model's scope.application_labels so state stays consistent after Create/Update/Read.
func (m *LifecyclePolicyResourceModel) fromAPIModel(ctx context.Context, apiModel LifecyclePolicyAPIModel, labelsFallback *LifecyclePolicyResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	// Set basic fields
	m.ID = types.StringValue(apiModel.ID)
	m.Name = types.StringValue(apiModel.Name)
	m.Enabled = types.BoolValue(apiModel.Enabled)
	m.Mode = types.StringValue(apiModel.Mode)

	// Handle description: API may return empty string or omit it entirely.
	// When API returns "", preserve the fallback (plan/state) value so that explicit description = "" stays "" in state.
	if apiModel.Description != "" {
		m.Description = types.StringValue(apiModel.Description)
	} else if labelsFallback != nil && !labelsFallback.Description.IsNull() {
		m.Description = labelsFallback.Description
	} else {
		m.Description = types.StringNull()
	}

	// Convert action
	if apiModel.Action != nil {
		actionAttrTypes := map[string]attr.Type{
			"type": types.StringType,
			"stage": types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"key":  types.StringType,
					"gate": types.StringType,
				},
			},
		}

		var stageValue attr.Value
		if apiModel.Action.Stage != nil {
			stageValue = types.ObjectValueMust(
				map[string]attr.Type{
					"key":  types.StringType,
					"gate": types.StringType,
				},
				map[string]attr.Value{
					"key":  types.StringValue(apiModel.Action.Stage.Key),
					"gate": types.StringValue(apiModel.Action.Stage.Gate),
				},
			)
		} else {
			stageValue = types.ObjectNull(map[string]attr.Type{
				"key":  types.StringType,
				"gate": types.StringType,
			})
		}

		actionValue := types.ObjectValueMust(
			actionAttrTypes,
			map[string]attr.Value{
				"type":  types.StringValue(apiModel.Action.Type),
				"stage": stageValue,
			},
		)
		m.Action = actionValue
	} else {
		m.Action = types.ObjectNull(map[string]attr.Type{
			"type": types.StringType,
			"stage": types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"key":  types.StringType,
					"gate": types.StringType,
				},
			},
		})
	}

	// Convert scope
	if apiModel.Scope != nil {
		scopeAttrTypes := map[string]attr.Type{
			"type":             types.StringType,
			"project_keys":     types.ListType{ElemType: types.StringType},
			"application_keys": types.ListType{ElemType: types.StringType},
			"application_labels": types.ListType{
				ElemType: types.ObjectType{
					AttrTypes: map[string]attr.Type{
						"key":   types.StringType,
						"value": types.StringType,
					},
				},
			},
		}

		// Convert project_keys
		var projectKeysValue attr.Value
		if len(apiModel.Scope.ProjectKeys) > 0 {
			projectKeys := make([]attr.Value, len(apiModel.Scope.ProjectKeys))
			for i, key := range apiModel.Scope.ProjectKeys {
				projectKeys[i] = types.StringValue(key)
			}
			projectKeysValue = types.ListValueMust(types.StringType, projectKeys)
		} else {
			projectKeysValue = types.ListNull(types.StringType)
		}

		// Convert application_keys
		var applicationKeysValue attr.Value
		if len(apiModel.Scope.ApplicationKeys) > 0 {
			applicationKeys := make([]attr.Value, len(apiModel.Scope.ApplicationKeys))
			for i, key := range apiModel.Scope.ApplicationKeys {
				applicationKeys[i] = types.StringValue(key)
			}
			applicationKeysValue = types.ListValueMust(types.StringType, applicationKeys)
		} else {
			applicationKeysValue = types.ListNull(types.StringType)
		}

		// Convert application_labels
		// NOTE: The API accepts application_labels in CREATE/UPDATE but does NOT return them in responses.
		// Preserve from labelsFallback when API returns none so Terraform state stays consistent after apply.
		applicationLabelsElemType := types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"key":   types.StringType,
				"value": types.StringType,
			},
		}
		var applicationLabelsValue attr.Value
		if len(apiModel.Scope.ApplicationLabels) > 0 {
			labels := make([]attr.Value, len(apiModel.Scope.ApplicationLabels))
			for i, label := range apiModel.Scope.ApplicationLabels {
				labels[i] = types.ObjectValueMust(
					applicationLabelsElemType.AttrTypes,
					map[string]attr.Value{
						"key":   types.StringValue(label.Key),
						"value": types.StringValue(label.Value),
					},
				)
			}
			applicationLabelsValue = types.ListValueMust(applicationLabelsElemType, labels)
		} else if labelsFallback != nil && !labelsFallback.Scope.IsNull() {
			scopeAttrs := labelsFallback.Scope.Attributes()
			if labelsAttr, ok := scopeAttrs["application_labels"]; ok && labelsAttr != nil {
				if listVal, ok := labelsAttr.(types.List); ok && !listVal.IsNull() {
					applicationLabelsValue = listVal
				} else {
					applicationLabelsValue = types.ListNull(applicationLabelsElemType)
				}
			} else {
				applicationLabelsValue = types.ListNull(applicationLabelsElemType)
			}
		} else {
			applicationLabelsValue = types.ListNull(applicationLabelsElemType)
		}

		scopeValue := types.ObjectValueMust(
			scopeAttrTypes,
			map[string]attr.Value{
				"type":               types.StringValue(apiModel.Scope.Type),
				"project_keys":       projectKeysValue,
				"application_keys":   applicationKeysValue,
				"application_labels": applicationLabelsValue,
			},
		)
		m.Scope = scopeValue
	} else {
		m.Scope = types.ObjectNull(map[string]attr.Type{
			"type":             types.StringType,
			"project_keys":     types.ListType{ElemType: types.StringType},
			"application_keys": types.ListType{ElemType: types.StringType},
			"application_labels": types.ListType{
				ElemType: types.ObjectType{
					AttrTypes: map[string]attr.Type{
						"key":   types.StringType,
						"value": types.StringType,
					},
				},
			},
		})
	}

	// Convert rule_ids (API returns rule_ids on Create/Get/Update/List)
	if len(apiModel.RuleIDs) > 0 {
		ruleIDValues := make([]attr.Value, len(apiModel.RuleIDs))
		for i, ruleID := range apiModel.RuleIDs {
			ruleIDValues[i] = types.StringValue(ruleID)
		}
		m.RuleIDs = types.ListValueMust(types.StringType, ruleIDValues)
	} else {
		m.RuleIDs = types.ListNull(types.StringType)
	}

	return diags
}

func (r *LifecyclePolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state LifecyclePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyID := state.ID.ValueString()
	if policyID == "" {
		resp.Diagnostics.AddError(
			"Missing Policy ID",
			"The policy ID is required to read the policy.",
		)
		return
	}

	tflog.Info(ctx, "Reading lifecycle policy", map[string]interface{}{
		"policy_id": policyID,
	})

	tflog.Debug(ctx, "API request details", map[string]interface{}{
		"endpoint":  PolicyEndpoint,
		"method":    "GET",
		"policy_id": policyID,
	})

	var apiResponse LifecyclePolicyAPIModel
	httpResponse, err := r.ProviderData.Client.R().
		SetContext(ctx).
		SetPathParam("policyId", policyID).
		SetResult(&apiResponse).
		Get(PolicyEndpoint)

	if err != nil {
		tflog.Error(ctx, "Failed to send read request", map[string]interface{}{
			"policy_id": policyID,
			"error":     err.Error(),
		})
		utilfw.UnableToRefreshResourceError(resp, err.Error())
		return
	}

	// API returns 200 OK on successful read
	if httpResponse.StatusCode() != http.StatusOK {
		if httpResponse.StatusCode() == http.StatusNotFound {
			tflog.Warn(ctx, "Policy not found, removing from state", map[string]interface{}{
				"policy_id": policyID,
			})
			resp.State.RemoveResource(ctx)
			return
		}
		// Log full response for debugging
		responseBody := string(httpResponse.Body())
		tflog.Error(ctx, "API returned error during read", map[string]interface{}{
			"policy_id":   policyID,
			"status_code": httpResponse.StatusCode(),
			"response":    responseBody,
		})
		errorDiags := unifiedpolicy.HandleAPIError(httpResponse, "read")
		resp.Diagnostics.Append(errorDiags...)
		return
	}

	tflog.Debug(ctx, "API read response received", map[string]interface{}{
		"policy_id":   apiResponse.ID,
		"status_code": httpResponse.StatusCode(),
	})

	diags := state.fromAPIModel(ctx, apiResponse, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Ensure ID is set
	state.ID = types.StringValue(apiResponse.ID)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *LifecyclePolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan LifecyclePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state LifecyclePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyID := plan.ID.ValueString()
	if policyID == "" {
		policyID = state.ID.ValueString()
	}

	apiModel, diags := plan.toAPIModel(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Updating lifecycle policy", map[string]interface{}{
		"policy_id": policyID,
	})

	tflog.Debug(ctx, "API request details", map[string]interface{}{
		"endpoint":  PolicyEndpoint,
		"method":    "PUT",
		"policy_id": policyID,
	})

	var apiResponse LifecyclePolicyAPIModel
	httpResponse, err := r.ProviderData.Client.R().
		SetContext(ctx).
		SetPathParam("policyId", policyID).
		SetBody(apiModel).
		SetResult(&apiResponse).
		Put(PolicyEndpoint)

	if err != nil {
		tflog.Error(ctx, "Failed to send update request", map[string]interface{}{
			"policy_id": policyID,
			"error":     err.Error(),
		})
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}

	// API returns 200 OK on successful update
	if httpResponse.StatusCode() != http.StatusOK {
		if httpResponse.StatusCode() == http.StatusNotFound {
			tflog.Warn(ctx, "Policy not found during update", map[string]interface{}{
				"policy_id": policyID,
			})
			resp.Diagnostics.AddError(
				"Policy Not Found",
				fmt.Sprintf("Policy with ID '%s' was not found. The policy may have been deleted.", policyID),
			)
			return
		}
		// Log full response for debugging
		responseBody := string(httpResponse.Body())
		tflog.Error(ctx, "API returned error during update", map[string]interface{}{
			"policy_id":   policyID,
			"status_code": httpResponse.StatusCode(),
			"response":    responseBody,
		})
		errorDiags := unifiedpolicy.HandleAPIError(httpResponse, "update")
		resp.Diagnostics.Append(errorDiags...)
		return
	}

	tflog.Debug(ctx, "API update response received", map[string]interface{}{
		"policy_id":   apiResponse.ID,
		"status_code": httpResponse.StatusCode(),
	})

	diags = plan.fromAPIModel(ctx, apiResponse, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Ensure ID is set
	plan.ID = types.StringValue(apiResponse.ID)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *LifecyclePolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state LifecyclePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyID := state.ID.ValueString()

	tflog.Info(ctx, "Deleting lifecycle policy", map[string]interface{}{
		"policy_id": policyID,
	})

	tflog.Debug(ctx, "API request details", map[string]interface{}{
		"endpoint":  PolicyEndpoint,
		"method":    "DELETE",
		"policy_id": policyID,
	})

	httpResponse, err := r.ProviderData.Client.R().
		SetContext(ctx).
		SetPathParam("policyId", policyID).
		Delete(PolicyEndpoint)

	if err != nil {
		tflog.Error(ctx, "Failed to send delete request", map[string]interface{}{
			"policy_id": policyID,
			"error":     err.Error(),
		})
		utilfw.UnableToDeleteResourceError(resp, err.Error())
		return
	}

	// API returns 204 No Content on successful delete
	if httpResponse.StatusCode() == http.StatusNoContent {
		tflog.Debug(ctx, "Lifecycle policy deleted successfully", map[string]interface{}{
			"policy_id":   policyID,
			"status_code": httpResponse.StatusCode(),
		})
		return
	}

	if httpResponse.StatusCode() == http.StatusNotFound {
		tflog.Warn(ctx, "Policy not found during delete, assuming already deleted", map[string]interface{}{
			"policy_id": policyID,
		})
		// Resource already deleted, nothing to do
		return
	}

	// Handle other error status codes
	responseBody := string(httpResponse.Body())
	tflog.Error(ctx, "API returned error during delete", map[string]interface{}{
		"policy_id":   policyID,
		"status_code": httpResponse.StatusCode(),
		"response":    responseBody,
	})
	errorDiags := unifiedpolicy.HandleAPIError(httpResponse, "delete")
	resp.Diagnostics.Append(errorDiags...)
}

func (r *LifecyclePolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
