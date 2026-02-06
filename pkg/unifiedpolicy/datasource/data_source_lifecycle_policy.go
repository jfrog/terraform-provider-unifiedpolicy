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
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy"
	"github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy/resource"
)

var _ datasource.DataSource = &LifecyclePolicyDataSource{}

func NewLifecyclePolicyDataSource() datasource.DataSource {
	return &LifecyclePolicyDataSource{}
}

type LifecyclePolicyDataSource struct {
	ProviderData util.ProviderMetadata
}

type LifecyclePolicyDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Mode        types.String `tfsdk:"mode"`
	Action      types.Object `tfsdk:"action"`
	Scope       types.Object `tfsdk:"scope"`
	RuleIDs     types.List   `tfsdk:"rule_ids"`
	CreatedAt   types.String `tfsdk:"created_at"`
	CreatedBy   types.String `tfsdk:"created_by"`
	UpdatedAt   types.String `tfsdk:"updated_at"`
	UpdatedBy   types.String `tfsdk:"updated_by"`
}

func (d *LifecyclePolicyDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_lifecycle_policy"
}

func (d *LifecyclePolicyDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Returns the details of a Unified Policy lifecycle policy by its ID. " +
			"This datasource can be used to query policy information such as enforcement mode, scope, rules, and lifecycle actions.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the lifecycle policy to query.",
				Required:    true,
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
								Description: "Lifecycle stage key (e.g., 'qa', 'production').",
								Computed:    true,
							},
							"gate": schema.StringAttribute{
								Description: "Lifecycle gate. One of: 'entry', 'exit', 'release'.",
								Computed:    true,
							},
						},
					},
				},
			},
			"scope": schema.SingleNestedAttribute{
				Description: "Where the policy applies (project-level or application-level).",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						Description: "Scope type. Either 'project' or 'application'.",
						Computed:    true,
					},
					"project_keys": schema.ListAttribute{
						Description: "Projects to include (for project scope).",
						ElementType: types.StringType,
						Computed:    true,
					},
					"application_keys": schema.ListAttribute{
						Description: "Applications to include (for application scope).",
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
	}
}

func (d *LifecyclePolicyDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (d *LifecyclePolicyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data LifecyclePolicyDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading lifecycle policy datasource", map[string]interface{}{
		"id": data.ID.ValueString(),
	})

	var result resource.LifecyclePolicyAPIModel
	response, err := d.ProviderData.Client.R().
		SetContext(ctx).
		SetPathParam("policyId", data.ID.ValueString()).
		SetResult(&result).
		Get(resource.PolicyEndpoint)

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
		if response.StatusCode() == http.StatusNotFound {
			resp.Diagnostics.AddError(
				"Lifecycle Policy Not Found",
				fmt.Sprintf("Lifecycle policy with ID '%s' was not found.", data.ID.ValueString()),
			)
			return
		}
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

// FromAPIModel converts the API response model to the Terraform datasource model.
func (m *LifecyclePolicyDataSourceModel) FromAPIModel(ctx context.Context, apiModel resource.LifecyclePolicyAPIModel) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringValue(apiModel.ID)
	m.Name = types.StringValue(apiModel.Name)

	if apiModel.Description != "" {
		m.Description = types.StringValue(apiModel.Description)
	} else {
		m.Description = types.StringNull()
	}

	m.Enabled = types.BoolValue(apiModel.Enabled)
	m.Mode = types.StringValue(apiModel.Mode)

	// Convert action
	if apiModel.Action != nil {
		actionAttrs := map[string]attr.Value{
			"type": types.StringValue(apiModel.Action.Type),
		}

		if apiModel.Action.Stage != nil {
			stageAttrs := map[string]attr.Value{
				"key":  types.StringValue(apiModel.Action.Stage.Key),
				"gate": types.StringValue(apiModel.Action.Stage.Gate),
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
			m.Action = actionObj
		}
	} else {
		m.Action = types.ObjectNull(map[string]attr.Type{
			"type": types.StringType,
			"stage": types.ObjectType{AttrTypes: map[string]attr.Type{
				"key":  types.StringType,
				"gate": types.StringType,
			}},
		})
	}

	// Convert scope
	if apiModel.Scope != nil {
		scopeAttrs := map[string]attr.Value{
			"type": types.StringValue(apiModel.Scope.Type),
		}

		// Project keys
		if len(apiModel.Scope.ProjectKeys) > 0 {
			projectKeys := make([]types.String, len(apiModel.Scope.ProjectKeys))
			for i, key := range apiModel.Scope.ProjectKeys {
				projectKeys[i] = types.StringValue(key)
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
		if len(apiModel.Scope.ApplicationKeys) > 0 {
			appKeys := make([]types.String, len(apiModel.Scope.ApplicationKeys))
			for i, key := range apiModel.Scope.ApplicationKeys {
				appKeys[i] = types.StringValue(key)
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
		if len(apiModel.Scope.ApplicationLabels) > 0 {
			labels := make([]types.Object, len(apiModel.Scope.ApplicationLabels))
			labelAttrTypes := map[string]attr.Type{
				"key":   types.StringType,
				"value": types.StringType,
			}
			for i, label := range apiModel.Scope.ApplicationLabels {
				labelAttrs := map[string]attr.Value{
					"key":   types.StringValue(label.Key),
					"value": types.StringValue(label.Value),
				}
				labelObj, labelDiags := types.ObjectValue(labelAttrTypes, labelAttrs)
				diags.Append(labelDiags...)
				if !diags.HasError() {
					labels[i] = labelObj
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
			m.Scope = scopeObj
		}
	} else {
		m.Scope = types.ObjectNull(map[string]attr.Type{
			"type":             types.StringType,
			"project_keys":     types.ListType{ElemType: types.StringType},
			"application_keys": types.ListType{ElemType: types.StringType},
			"application_labels": types.ListType{ElemType: types.ObjectType{AttrTypes: map[string]attr.Type{
				"key":   types.StringType,
				"value": types.StringType,
			}}},
		})
	}

	// Rule IDs (API returns rule_ids)
	if len(apiModel.RuleIDs) > 0 {
		ruleIDValues := make([]types.String, len(apiModel.RuleIDs))
		for i, ruleID := range apiModel.RuleIDs {
			ruleIDValues[i] = types.StringValue(ruleID)
		}
		ruleIDsList, ruleDiags := types.ListValueFrom(ctx, types.StringType, ruleIDValues)
		diags.Append(ruleDiags...)
		if !diags.HasError() {
			m.RuleIDs = ruleIDsList
		}
	} else {
		m.RuleIDs = types.ListNull(types.StringType)
	}

	// Timestamps
	if apiModel.CreatedAt != "" {
		m.CreatedAt = types.StringValue(apiModel.CreatedAt)
	} else {
		m.CreatedAt = types.StringNull()
	}

	if apiModel.CreatedBy != "" {
		m.CreatedBy = types.StringValue(apiModel.CreatedBy)
	} else {
		m.CreatedBy = types.StringNull()
	}

	if apiModel.UpdatedAt != "" {
		m.UpdatedAt = types.StringValue(apiModel.UpdatedAt)
	} else {
		m.UpdatedAt = types.StringNull()
	}

	if apiModel.UpdatedBy != "" {
		m.UpdatedBy = types.StringValue(apiModel.UpdatedBy)
	} else {
		m.UpdatedBy = types.StringNull()
	}

	return diags
}
