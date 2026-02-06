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

var _ datasource.DataSource = &RuleDataSource{}

func NewRuleDataSource() datasource.DataSource {
	return &RuleDataSource{}
}

type RuleDataSource struct {
	ProviderData util.ProviderMetadata
}

type RuleDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	IsCustom    types.Bool   `tfsdk:"is_custom"`
	TemplateID  types.String `tfsdk:"template_id"`
	Parameters  types.List   `tfsdk:"parameters"`
	CreatedAt   types.String `tfsdk:"created_at"`
	CreatedBy   types.String `tfsdk:"created_by"`
	UpdatedAt   types.String `tfsdk:"updated_at"`
	UpdatedBy   types.String `tfsdk:"updated_by"`
}

func (d *RuleDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_rule"
}

func (d *RuleDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Returns the details of a Unified Policy rule by its ID. " +
			"Rules define the specific parameter values for policy evaluation and are based on rule templates.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the rule to query.",
				Required:    true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the rule.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "Free-text description of the rule purpose.",
				Computed:    true,
			},
			"is_custom": schema.BoolAttribute{
				Description: "Indicates if the rule is user-defined (true) or predefined (false).",
				Computed:    true,
			},
			"template_id": schema.StringAttribute{
				Description: "The ID of the template the rule is based on.",
				Computed:    true,
			},
			"parameters": schema.ListNestedAttribute{
				Description: "Array of parameter name/value pairs that match the template definition.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Description: "Name of the template parameter.",
							Computed:    true,
						},
						"value": schema.StringAttribute{
							Description: "The value assigned to the parameter.",
							Computed:    true,
						},
					},
				},
			},
			"created_at": schema.StringAttribute{
				Description: "Timestamp when the rule was created.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "User who created the rule.",
				Computed:    true,
			},
			"updated_at": schema.StringAttribute{
				Description: "Timestamp when the rule was last updated.",
				Computed:    true,
			},
			"updated_by": schema.StringAttribute{
				Description: "User who last updated the rule.",
				Computed:    true,
			},
		},
	}
}

func (d *RuleDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (d *RuleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data RuleDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading rule datasource", map[string]interface{}{
		"id": data.ID.ValueString(),
	})

	var result resource.RuleAPIModel
	response, err := d.ProviderData.Client.R().
		SetContext(ctx).
		SetPathParam("rule_id", data.ID.ValueString()).
		SetResult(&result).
		Get(resource.RuleEndpoint)

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
				"Rule Not Found",
				fmt.Sprintf("Rule with ID '%s' was not found.", data.ID.ValueString()),
			)
			return
		}
		diags := unifiedpolicy.HandleAPIErrorWithType(response, "read", "rule")
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
func (m *RuleDataSourceModel) FromAPIModel(ctx context.Context, apiModel resource.RuleAPIModel) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringValue(apiModel.ID)
	m.Name = types.StringValue(apiModel.Name)
	m.TemplateID = types.StringValue(apiModel.TemplateID)
	m.IsCustom = types.BoolValue(apiModel.IsCustom)

	if apiModel.Description != "" {
		m.Description = types.StringValue(apiModel.Description)
	} else {
		m.Description = types.StringNull()
	}

	// Parameters
	paramAttrTypes := map[string]attr.Type{
		"name":  types.StringType,
		"value": types.StringType,
	}
	if len(apiModel.Parameters) > 0 {
		parameters := make([]types.Object, len(apiModel.Parameters))
		for i, param := range apiModel.Parameters {
			paramAttrs := map[string]attr.Value{
				"name":  types.StringValue(param.Name),
				"value": types.StringValue(param.Value),
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
			m.Parameters = types.ListNull(types.ObjectType{AttrTypes: paramAttrTypes})
		}
	} else {
		m.Parameters = types.ListNull(types.ObjectType{AttrTypes: paramAttrTypes})
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
