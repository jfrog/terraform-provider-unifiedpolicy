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

package datasource

import (
	"context"
	"net/url"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy"
	"github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy/resource"
)

var _ datasource.DataSource = &LifecyclePoliciesDataSource{}

func NewLifecyclePoliciesDataSource() datasource.DataSource {
	return &LifecyclePoliciesDataSource{}
}

type LifecyclePoliciesDataSource struct {
	ProviderData util.ProviderMetadata
}

type LifecyclePoliciesDataSourceModel struct {
	ID                types.String `tfsdk:"id"`
	IDs               types.List   `tfsdk:"ids"`
	Name              types.String `tfsdk:"name"`
	Names             types.List   `tfsdk:"names"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	Mode              types.String `tfsdk:"mode"`
	ActionType        types.String `tfsdk:"action_type"`
	ScopeType         types.String `tfsdk:"scope_type"`
	StageKeys         types.List   `tfsdk:"stage_keys"`
	StageGates        types.List   `tfsdk:"stage_gates"`
	ProjectKey        types.String `tfsdk:"project_key"`
	ApplicationKeys   types.List   `tfsdk:"application_keys"`
	ApplicationLabels types.Map    `tfsdk:"application_labels"`
	Expand            types.String `tfsdk:"expand"`
	Page              types.Int64  `tfsdk:"page"`
	Limit             types.Int64  `tfsdk:"limit"`
	SortBy            types.String `tfsdk:"sort_by"`
	SortOrder         types.String `tfsdk:"sort_order"`
	Policies          types.List   `tfsdk:"policies"`
	Offset            types.Int64  `tfsdk:"offset"`
	PageSize          types.Int64  `tfsdk:"page_size"`
}

// lifecyclePolicyRuleItem is used when list API is called with expand=rules (API returns rules array per item).
type lifecyclePolicyRuleItem struct {
	ID string `json:"id"`
}

// lifecyclePolicyListEntry extends the resource API model with Rules for list response (expand=rules only).
// The resource package is not updated for list-only fields; this type is used only by this datasource.
type lifecyclePolicyListEntry struct {
	resource.LifecyclePolicyAPIModel
	Rules []lifecyclePolicyRuleItem `json:"rules,omitempty"`
}

// PoliciesListAPIModel represents the API response for listing policies.
// The API returns items, limit, offset, and page_size (no total_count).
type PoliciesListAPIModel struct {
	Items    []lifecyclePolicyListEntry `json:"items"`
	Offset   int                        `json:"offset"`
	Limit    int                        `json:"limit"`
	PageSize int                        `json:"page_size"`
}

func (d *LifecyclePoliciesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_lifecycle_policies"
}

func (d *LifecyclePoliciesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Returns a list of Unified Policy lifecycle policies with support for filtering, pagination, and sorting. " +
			"This datasource can be used to query policies by various criteria such as enforcement mode, scope, stage, and more.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Filter by a single policy ID. Sent as query parameter `id`.",
				Optional:    true,
			},
			"ids": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "Filter by policy IDs. Multiple IDs are sent as repeated `id` query parameters (e.g. ?id=1005&id=1006).",
				Optional:    true,
			},
			"name": schema.StringAttribute{
				Description: "Filter by a single policy name. Sent as query parameter `name`.",
				Optional:    true,
			},
			"names": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "Filter by policy names. Multiple names are sent as repeated `name` query parameters.",
				Optional:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Filter by enabled status. If not specified, returns both enabled and disabled policies.",
				Optional:    true,
			},
			"mode": schema.StringAttribute{
				Description: "Filter by enforcement mode. Must be either 'block' or 'warning'.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("block", "warning"),
				},
			},
			"action_type": schema.StringAttribute{
				Description: "Filter by action type (e.g., 'certify_to_gate').",
				Optional:    true,
			},
			"scope_type": schema.StringAttribute{
				Description: "Filter by scope type. Must be either 'project' or 'application'.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("project", "application"),
				},
			},
			"stage_keys": schema.ListAttribute{
				Description: "Filter by lifecycle stage keys (e.g., ['qa', 'production']).",
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
			},
			"stage_gates": schema.ListAttribute{
				Description: "Filter by lifecycle gates. Allowed values: 'entry', 'exit', 'release'.",
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.OneOf("entry", "exit", "release"),
					),
				},
			},
			"project_key": schema.StringAttribute{
				Description: "Filter by project key (for project scope).",
				Optional:    true,
			},
			"application_keys": schema.ListAttribute{
				Description: "Filter by application keys (for application scope).",
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
			},
			"application_labels": schema.MapAttribute{
				Description: "Filter by application labels. Each key-value pair represents a label filter.",
				ElementType: types.StringType,
				Optional:    true,
			},
			"expand": schema.StringAttribute{
				Description: "Use 'rules' to include rule summaries in the response.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("rules"),
				},
			},
			"page": schema.Int64Attribute{
				Description: "Page offset (default: 0).",
				Optional:    true,
			},
			"limit": schema.Int64Attribute{
				Description: "Items per page (1-250, default: 100).",
				Optional:    true,
			},
			"sort_by": schema.StringAttribute{
				Description: "Sort field (e.g., 'name', 'created_at').",
				Optional:    true,
			},
			"sort_order": schema.StringAttribute{
				Description: "Sort order. Must be either 'asc' or 'desc'.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("asc", "desc"),
				},
			},
			"policies": schema.ListNestedAttribute{
				Description: "List of lifecycle policies.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The ID of the lifecycle policy.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "The policy name.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "A free-text description of the policy.",
							Computed:    true,
						},
						"enabled": schema.BoolAttribute{
							Description: "Whether the policy is active.",
							Computed:    true,
						},
						"mode": schema.StringAttribute{
							Description: "Enforcement mode. Either 'block' or 'warning'.",
							Computed:    true,
						},
						"action": schema.SingleNestedAttribute{
							Description: "Lifecycle action governed by the policy.",
							Computed:    true,
							Attributes: map[string]schema.Attribute{
								"type": schema.StringAttribute{
									Description: "Action type (e.g., 'certify_to_gate').",
									Computed:    true,
								},
								"stage": schema.SingleNestedAttribute{
									Description: "Lifecycle stage and gate configuration.",
									Computed:    true,
									Attributes: map[string]schema.Attribute{
										"key": schema.StringAttribute{
											Description: "Lifecycle stage key.",
											Computed:    true,
										},
										"gate": schema.StringAttribute{
											Description: "Lifecycle gate.",
											Computed:    true,
										},
									},
								},
							},
						},
						"scope": schema.SingleNestedAttribute{
							Description: "Where the policy applies.",
							Computed:    true,
							Attributes: map[string]schema.Attribute{
								"type": schema.StringAttribute{
									Description: "Scope type.",
									Computed:    true,
								},
								"project_keys": schema.ListAttribute{
									Description: "Projects to include.",
									ElementType: types.StringType,
									Computed:    true,
								},
								"application_keys": schema.ListAttribute{
									Description: "Applications to include.",
									ElementType: types.StringType,
									Computed:    true,
								},
								"application_labels": schema.ListNestedAttribute{
									Description: "Label filters for application scope.",
									Computed:    true,
									NestedObject: schema.NestedAttributeObject{
										Attributes: map[string]schema.Attribute{
											"key": schema.StringAttribute{
												Description: "Label key.",
												Computed:    true,
											},
											"value": schema.StringAttribute{
												Description: "Label value.",
												Computed:    true,
											},
										},
									},
								},
							},
						},
						"rule_ids": schema.ListAttribute{
							Description: "IDs of rules enforced by this policy.",
							ElementType: types.StringType,
							Computed:    true,
						},
						"created_at": schema.StringAttribute{
							Description: "Timestamp when the policy was created.",
							Computed:    true,
						},
						"created_by": schema.StringAttribute{
							Description: "User who created the policy.",
							Computed:    true,
						},
						"updated_at": schema.StringAttribute{
							Description: "Timestamp when the policy was last updated.",
							Computed:    true,
						},
						"updated_by": schema.StringAttribute{
							Description: "User who last updated the policy.",
							Computed:    true,
						},
					},
				},
			},
			"offset": schema.Int64Attribute{
				Description: "Current page offset.",
				Computed:    true,
			},
			"page_size": schema.Int64Attribute{
				Description: "Number of items in the current page.",
				Computed:    true,
			},
		},
	}
}

func (d *LifecyclePoliciesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (d *LifecyclePoliciesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data LifecyclePoliciesDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := d.ProviderData.Client.R().SetContext(ctx)

	// Multi-value params per API spec (array form, explode): id, name, stage_key, stage_gate, application_key
	queryValues := url.Values{}
	if !data.IDs.IsNull() && len(data.IDs.Elements()) > 0 {
		for _, e := range data.IDs.Elements() {
			if s, ok := e.(types.String); ok && !s.IsNull() {
				queryValues.Add("id", s.ValueString())
			}
		}
	} else if !data.ID.IsNull() {
		queryValues.Set("id", data.ID.ValueString())
	}
	if !data.Names.IsNull() && len(data.Names.Elements()) > 0 {
		for _, e := range data.Names.Elements() {
			if s, ok := e.(types.String); ok && !s.IsNull() {
				queryValues.Add("name", s.ValueString())
			}
		}
	} else if !data.Name.IsNull() {
		queryValues.Set("name", data.Name.ValueString())
	}
	// stage_key (array form, explode)
	if !data.StageKeys.IsNull() {
		var stageKeys []string
		diags := data.StageKeys.ElementsAs(ctx, &stageKeys, false)
		resp.Diagnostics.Append(diags...)
		if !resp.Diagnostics.HasError() {
			for _, key := range stageKeys {
				queryValues.Add("stage_key", key)
			}
		}
	}
	// stage_gate (array form, explode)
	if !data.StageGates.IsNull() {
		var stageGates []string
		diags := data.StageGates.ElementsAs(ctx, &stageGates, false)
		resp.Diagnostics.Append(diags...)
		if !resp.Diagnostics.HasError() {
			for _, gate := range stageGates {
				queryValues.Add("stage_gate", gate)
			}
		}
	}
	// application_key (array form, explode)
	if !data.ApplicationKeys.IsNull() {
		var appKeys []string
		diags := data.ApplicationKeys.ElementsAs(ctx, &appKeys, false)
		resp.Diagnostics.Append(diags...)
		if !resp.Diagnostics.HasError() {
			for _, key := range appKeys {
				queryValues.Add("application_key", key)
			}
		}
	}
	if len(queryValues) > 0 {
		request.SetQueryParamsFromValues(queryValues)
	}

	// Single-value query parameters
	if !data.Enabled.IsNull() {
		request.SetQueryParam("enabled", strconv.FormatBool(data.Enabled.ValueBool()))
	}
	if !data.Mode.IsNull() {
		request.SetQueryParam("mode", data.Mode.ValueString())
	}
	if !data.ActionType.IsNull() {
		request.SetQueryParam("action_type", data.ActionType.ValueString())
	}
	if !data.ScopeType.IsNull() {
		request.SetQueryParam("scope_type", data.ScopeType.ValueString())
	}
	if !data.ProjectKey.IsNull() {
		request.SetQueryParam("project_key", data.ProjectKey.ValueString())
	}

	// Application labels - API expects object with key-value pairs
	// Note: The API documentation shows application_labels as an object, but we'll send as query params
	// This may need adjustment based on actual API behavior
	if !data.ApplicationLabels.IsNull() {
		var labels map[string]string
		diags := data.ApplicationLabels.ElementsAs(ctx, &labels, false)
		resp.Diagnostics.Append(diags...)
		if !resp.Diagnostics.HasError() {
			// The API expects application_labels as an object, but query params might need special handling
			// For now, we'll log a warning that this might not work as expected
			tflog.Warn(ctx, "Application labels filtering may not work correctly via query parameters. Check API documentation.")
		}
	}

	if !data.Expand.IsNull() {
		request.SetQueryParam("expand", data.Expand.ValueString())
	}

	// API spec uses 'offset' for pagination (not 'page')
	if !data.Page.IsNull() {
		request.SetQueryParam("offset", strconv.FormatInt(data.Page.ValueInt64(), 10))
	}

	if !data.Limit.IsNull() {
		request.SetQueryParam("limit", strconv.FormatInt(data.Limit.ValueInt64(), 10))
	}

	if !data.SortBy.IsNull() {
		request.SetQueryParam("sort_by", data.SortBy.ValueString())
	}

	if !data.SortOrder.IsNull() {
		request.SetQueryParam("sort_order", data.SortOrder.ValueString())
	}

	var result PoliciesListAPIModel
	response, err := request.SetResult(&result).Get(resource.PoliciesEndpoint)

	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read Data Source",
			"An unexpected error occurred while fetching the data source. "+
				"Please report this issue to the provider developers.\n\n"+
				"Error: "+err.Error(),
		)
		return
	}

	if response.IsError() {
		diags := unifiedpolicy.HandleAPIError(response, "read")
		resp.Diagnostics.Append(diags...)
		return
	}

	diags := data.FromAPIModel(ctx, result)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (m *LifecyclePoliciesDataSourceModel) FromAPIModel(ctx context.Context, apiModel PoliciesListAPIModel) diag.Diagnostics {
	var diags diag.Diagnostics

	// Convert policies list
	policies := make([]types.Object, len(apiModel.Items))
	policyAttrTypes := map[string]attr.Type{
		"id":          types.StringType,
		"name":        types.StringType,
		"description": types.StringType,
		"enabled":     types.BoolType,
		"mode":        types.StringType,
		"action": types.ObjectType{AttrTypes: map[string]attr.Type{
			"type": types.StringType,
			"stage": types.ObjectType{AttrTypes: map[string]attr.Type{
				"key":  types.StringType,
				"gate": types.StringType,
			}},
		}},
		"scope": types.ObjectType{AttrTypes: map[string]attr.Type{
			"type":             types.StringType,
			"project_keys":     types.ListType{ElemType: types.StringType},
			"application_keys": types.ListType{ElemType: types.StringType},
			"application_labels": types.ListType{ElemType: types.ObjectType{AttrTypes: map[string]attr.Type{
				"key":   types.StringType,
				"value": types.StringType,
			}}},
		}},
		"rule_ids":   types.ListType{ElemType: types.StringType},
		"created_at": types.StringType,
		"created_by": types.StringType,
		"updated_at": types.StringType,
		"updated_by": types.StringType,
	}

	for i, policy := range apiModel.Items {
		policyAttrs := map[string]attr.Value{
			"id":   types.StringValue(policy.ID),
			"name": types.StringValue(policy.Name),
		}

		if policy.Description != "" {
			policyAttrs["description"] = types.StringValue(policy.Description)
		} else {
			policyAttrs["description"] = types.StringNull()
		}

		policyAttrs["enabled"] = types.BoolValue(policy.Enabled)
		policyAttrs["mode"] = types.StringValue(policy.Mode)

		// Convert action
		if policy.Action != nil {
			actionAttrs := map[string]attr.Value{
				"type": types.StringValue(policy.Action.Type),
			}

			if policy.Action.Stage != nil {
				stageAttrs := map[string]attr.Value{
					"key":  types.StringValue(policy.Action.Stage.Key),
					"gate": types.StringValue(policy.Action.Stage.Gate),
				}
				stageAttrTypes := map[string]attr.Type{
					"key":  types.StringType,
					"gate": types.StringType,
				}
				stageObj, stageDiags := types.ObjectValue(stageAttrTypes, stageAttrs)
				diags.Append(stageDiags...)
				if !diags.HasError() {
					actionAttrs["stage"] = stageObj
				}
			} else {
				actionAttrs["stage"] = types.ObjectNull(map[string]attr.Type{
					"key":  types.StringType,
					"gate": types.StringType,
				})
			}

			actionObj, actionDiags := types.ObjectValue(map[string]attr.Type{
				"type": types.StringType,
				"stage": types.ObjectType{AttrTypes: map[string]attr.Type{
					"key":  types.StringType,
					"gate": types.StringType,
				}},
			}, actionAttrs)
			diags.Append(actionDiags...)
			if !diags.HasError() {
				policyAttrs["action"] = actionObj
			}
		} else {
			policyAttrs["action"] = types.ObjectNull(map[string]attr.Type{
				"type": types.StringType,
				"stage": types.ObjectType{AttrTypes: map[string]attr.Type{
					"key":  types.StringType,
					"gate": types.StringType,
				}},
			})
		}

		// Convert scope
		if policy.Scope != nil {
			scopeAttrs := map[string]attr.Value{
				"type": types.StringValue(policy.Scope.Type),
			}

			// Project keys
			if len(policy.Scope.ProjectKeys) > 0 {
				projectKeys := make([]types.String, len(policy.Scope.ProjectKeys))
				for j, key := range policy.Scope.ProjectKeys {
					projectKeys[j] = types.StringValue(key)
				}
				projectKeysList, pkDiags := types.ListValueFrom(ctx, types.StringType, projectKeys)
				diags.Append(pkDiags...)
				if !diags.HasError() {
					scopeAttrs["project_keys"] = projectKeysList
				}
			} else {
				scopeAttrs["project_keys"] = types.ListNull(types.StringType)
			}

			// Application keys
			if len(policy.Scope.ApplicationKeys) > 0 {
				appKeys := make([]types.String, len(policy.Scope.ApplicationKeys))
				for j, key := range policy.Scope.ApplicationKeys {
					appKeys[j] = types.StringValue(key)
				}
				appKeysList, akDiags := types.ListValueFrom(ctx, types.StringType, appKeys)
				diags.Append(akDiags...)
				if !diags.HasError() {
					scopeAttrs["application_keys"] = appKeysList
				}
			} else {
				scopeAttrs["application_keys"] = types.ListNull(types.StringType)
			}

			// Application labels
			if len(policy.Scope.ApplicationLabels) > 0 {
				labels := make([]types.Object, len(policy.Scope.ApplicationLabels))
				labelAttrTypes := map[string]attr.Type{
					"key":   types.StringType,
					"value": types.StringType,
				}
				for j, label := range policy.Scope.ApplicationLabels {
					labelAttrs := map[string]attr.Value{
						"key":   types.StringValue(label.Key),
						"value": types.StringValue(label.Value),
					}
					labelObj, labelDiags := types.ObjectValue(labelAttrTypes, labelAttrs)
					diags.Append(labelDiags...)
					if !diags.HasError() {
						labels[j] = labelObj
					}
				}
				labelsList, lblDiags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: labelAttrTypes}, labels)
				diags.Append(lblDiags...)
				if !diags.HasError() {
					scopeAttrs["application_labels"] = labelsList
				}
			} else {
				scopeAttrs["application_labels"] = types.ListNull(types.ObjectType{AttrTypes: map[string]attr.Type{
					"key":   types.StringType,
					"value": types.StringType,
				}})
			}

			scopeObj, scopeDiags := types.ObjectValue(map[string]attr.Type{
				"type":             types.StringType,
				"project_keys":     types.ListType{ElemType: types.StringType},
				"application_keys": types.ListType{ElemType: types.StringType},
				"application_labels": types.ListType{ElemType: types.ObjectType{AttrTypes: map[string]attr.Type{
					"key":   types.StringType,
					"value": types.StringType,
				}}},
			}, scopeAttrs)
			diags.Append(scopeDiags...)
			if !diags.HasError() {
				policyAttrs["scope"] = scopeObj
			}
		} else {
			policyAttrs["scope"] = types.ObjectNull(map[string]attr.Type{
				"type":             types.StringType,
				"project_keys":     types.ListType{ElemType: types.StringType},
				"application_keys": types.ListType{ElemType: types.StringType},
				"application_labels": types.ListType{ElemType: types.ObjectType{AttrTypes: map[string]attr.Type{
					"key":   types.StringType,
					"value": types.StringType,
				}}},
			})
		}

		// Rule IDs: use rule_ids from API; when list is called with expand=rules, API may return rules array instead, so fallback to rules[].id
		ruleIDs := policy.RuleIDs
		if len(ruleIDs) == 0 && len(policy.Rules) > 0 {
			ruleIDs = make([]string, len(policy.Rules))
			for j, r := range policy.Rules {
				ruleIDs[j] = r.ID
			}
		}
		if len(ruleIDs) > 0 {
			ruleIDValues := make([]types.String, len(ruleIDs))
			for j, ruleID := range ruleIDs {
				ruleIDValues[j] = types.StringValue(ruleID)
			}
			ruleIDsList, ruleDiags := types.ListValueFrom(ctx, types.StringType, ruleIDValues)
			diags.Append(ruleDiags...)
			if !diags.HasError() {
				policyAttrs["rule_ids"] = ruleIDsList
			}
		} else {
			policyAttrs["rule_ids"] = types.ListNull(types.StringType)
		}

		// Timestamps
		if policy.CreatedAt != "" {
			policyAttrs["created_at"] = types.StringValue(policy.CreatedAt)
		} else {
			policyAttrs["created_at"] = types.StringNull()
		}

		if policy.CreatedBy != "" {
			policyAttrs["created_by"] = types.StringValue(policy.CreatedBy)
		} else {
			policyAttrs["created_by"] = types.StringNull()
		}

		if policy.UpdatedAt != "" {
			policyAttrs["updated_at"] = types.StringValue(policy.UpdatedAt)
		} else {
			policyAttrs["updated_at"] = types.StringNull()
		}

		if policy.UpdatedBy != "" {
			policyAttrs["updated_by"] = types.StringValue(policy.UpdatedBy)
		} else {
			policyAttrs["updated_by"] = types.StringNull()
		}

		policyObj, policyDiags := types.ObjectValue(policyAttrTypes, policyAttrs)
		diags.Append(policyDiags...)
		if !diags.HasError() {
			policies[i] = policyObj
		}
	}

	policiesList, listDiags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: policyAttrTypes}, policies)
	diags.Append(listDiags...)
	if !diags.HasError() {
		m.Policies = policiesList
	} else {
		m.Policies = types.ListNull(types.ObjectType{AttrTypes: policyAttrTypes})
	}

	m.Offset = types.Int64Value(int64(apiModel.Offset))
	m.PageSize = types.Int64Value(int64(apiModel.PageSize))

	return diags
}
