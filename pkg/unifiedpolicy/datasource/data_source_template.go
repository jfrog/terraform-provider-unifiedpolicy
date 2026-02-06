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

var _ datasource.DataSource = &TemplateDataSource{}

func NewTemplateDataSource() datasource.DataSource {
	return &TemplateDataSource{}
}

type TemplateDataSource struct {
	ProviderData util.ProviderMetadata
}

type TemplateDataSourceModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	Description    types.String `tfsdk:"description"`
	Category       types.String `tfsdk:"category"`
	DataSourceType types.String `tfsdk:"data_source_type"`
	Parameters     types.List   `tfsdk:"parameters"`
	Rego           types.String `tfsdk:"rego"`
	Scanners       types.List   `tfsdk:"scanners"`
	IsCustom       types.Bool   `tfsdk:"is_custom"`
	CreatedAt      types.String `tfsdk:"created_at"`
	CreatedBy      types.String `tfsdk:"created_by"`
	UpdatedAt      types.String `tfsdk:"updated_at"`
	UpdatedBy      types.String `tfsdk:"updated_by"`
}

func (d *TemplateDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_template"
}

func (d *TemplateDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Returns the details of a Unified Policy template by its ID. " +
			"Templates define reusable logic (business rules) for policies using Rego policy language.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the template to query.",
				Required:    true,
			},
			"name": schema.StringAttribute{
				Description: "The template name.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "A free-text description of the template.",
				Computed:    true,
			},
			"category": schema.StringAttribute{
				Description: "Template category. One of: security, legal, operational, quality, audit, workflow.",
				Computed:    true,
			},
			"data_source_type": schema.StringAttribute{
				Description: "The type of data source the template expects. One of: noop, evidence, xray.",
				Computed:    true,
			},
			"parameters": schema.ListNestedAttribute{
				Description: "List of configurable parameters for the template.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Description: "Parameter name.",
							Computed:    true,
						},
						"type": schema.StringAttribute{
							Description: "Parameter type. One of: string, bool, int, float, object.",
							Computed:    true,
						},
					},
				},
			},
			"rego": schema.StringAttribute{
				Description: "Rego policy language code for evaluation (Open Policy Agent policy language).",
				Computed:    true,
			},
			"scanners": schema.ListAttribute{
				Description: "List of scanner types that this template supports. Allowed values: secrets, sca, exposures, contextual_analysis, malicious_package.",
				ElementType: types.StringType,
				Computed:    true,
			},
			"is_custom": schema.BoolAttribute{
				Description: "Whether the template is user-defined (true) or built-in (false).",
				Computed:    true,
			},
			"created_at": schema.StringAttribute{
				Description: "Timestamp when the template was created.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "User who created the template.",
				Computed:    true,
			},
			"updated_at": schema.StringAttribute{
				Description: "Timestamp when the template was last updated.",
				Computed:    true,
			},
			"updated_by": schema.StringAttribute{
				Description: "User who last updated the template.",
				Computed:    true,
			},
		},
	}
}

func (d *TemplateDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (d *TemplateDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data TemplateDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading template datasource", map[string]interface{}{
		"id": data.ID.ValueString(),
	})

	var result resource.TemplateAPIModel
	response, err := d.ProviderData.Client.R().
		SetContext(ctx).
		SetPathParam("templateId", data.ID.ValueString()).
		SetResult(&result).
		Get(resource.TemplateEndpoint)

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
				"Template Not Found",
				fmt.Sprintf("Template with ID '%s' was not found.", data.ID.ValueString()),
			)
			return
		}
		diags := unifiedpolicy.HandleAPIErrorWithType(response, "read", "template")
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
func (m *TemplateDataSourceModel) FromAPIModel(ctx context.Context, apiModel resource.TemplateAPIModel) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringValue(apiModel.ID)
	m.Name = types.StringValue(apiModel.Name)

	// Handle description: if pointer is nil, set to null; otherwise use the value (even if empty string)
	if apiModel.Description != nil {
		m.Description = types.StringValue(*apiModel.Description)
	} else {
		m.Description = types.StringNull()
	}

	m.Category = types.StringValue(apiModel.Category)
	m.DataSourceType = types.StringValue(apiModel.DataSourceType)
	m.Rego = types.StringValue(apiModel.Rego)
	m.IsCustom = types.BoolValue(apiModel.IsCustom)

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
			m.Parameters = types.ListNull(types.ObjectType{AttrTypes: paramAttrTypes})
		}
	} else {
		m.Parameters = types.ListNull(types.ObjectType{AttrTypes: paramAttrTypes})
	}

	// Convert scanners
	if len(apiModel.Scanners) > 0 {
		scanners := make([]types.String, len(apiModel.Scanners))
		for i, scanner := range apiModel.Scanners {
			scanners[i] = types.StringValue(scanner)
		}
		scannersList, scannerDiags := types.ListValueFrom(ctx, types.StringType, scanners)
		diags.Append(scannerDiags...)
		if !diags.HasError() {
			m.Scanners = scannersList
		}
	} else {
		m.Scanners = types.ListNull(types.StringType)
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
