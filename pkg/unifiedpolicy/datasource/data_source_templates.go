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

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy"
	"github.com/jfrog/terraform-provider-unifiedpolicy/pkg/unifiedpolicy/resource"
)

var _ datasource.DataSource = &TemplatesDataSource{}

func NewTemplatesDataSource() datasource.DataSource {
	return &TemplatesDataSource{}
}

type TemplatesDataSource struct {
	ProviderData util.ProviderMetadata
}

type TemplatesDataSourceModel struct {
	ID        types.String `tfsdk:"id"`
	IDs       types.List   `tfsdk:"ids"`
	Name      types.String `tfsdk:"name"`
	Names     types.List   `tfsdk:"names"`
	Category  types.String `tfsdk:"category"`
	Page      types.Int64  `tfsdk:"page"`
	Limit     types.Int64  `tfsdk:"limit"`
	SortBy    types.String `tfsdk:"sort_by"`
	SortOrder types.String `tfsdk:"sort_order"`
	Templates types.List   `tfsdk:"templates"`
	Offset    types.Int64  `tfsdk:"offset"`
	PageSize  types.Int64  `tfsdk:"page_size"`
}

func (d *TemplatesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_templates"
}

func (d *TemplatesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Returns a list of Unified Policy templates with support for filtering, pagination, and sorting. " +
			"This datasource can be used to query templates by various criteria such as category, name, and more.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Filter by a single template ID. Sent as query parameter `id`.",
				Optional:    true,
			},
			"ids": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "Filter by template IDs. Multiple IDs are sent as repeated `id` query parameters (e.g. ?id=1005&id=1004).",
				Optional:    true,
			},
			"name": schema.StringAttribute{
				Description: "Filter by a single template name. Sent as query parameter `name`.",
				Optional:    true,
			},
			"names": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "Filter by template names. Multiple names are sent as repeated `name` query parameters (e.g. ?name=foo&name=bar).",
				Optional:    true,
			},
			"category": schema.StringAttribute{
				Description: "Filter by template category. Must be one of: security, legal, operational, quality, audit, workflow.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("security", "legal", "operational", "quality", "audit", "workflow"),
				},
			},
			"page": schema.Int64Attribute{
				Description: "Pagination offset (default: 0). Sent to API as 'offset' per spec.",
				Optional:    true,
			},
			"limit": schema.Int64Attribute{
				Description: "Items per page (1-1000, default: 100).",
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
			"templates": schema.ListNestedAttribute{
				Description: "List of templates returned by the API.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The ID of the template.",
							Computed:    true,
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
							Description: "Template category.",
							Computed:    true,
						},
						"data_source_type": schema.StringAttribute{
							Description: "The type of data source the template expects.",
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
						"updated_at": schema.StringAttribute{
							Description: "Timestamp when the template was last updated.",
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

func (d *TemplatesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (d *TemplatesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data TemplatesDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := d.ProviderData.Client.R().SetContext(ctx)

	// Build multi-value query params (id, name) in one Values so both can be sent
	queryValues := url.Values{}
	if !data.IDs.IsNull() && len(data.IDs.Elements()) > 0 {
		idStrings := make([]string, 0, len(data.IDs.Elements()))
		for _, e := range data.IDs.Elements() {
			if s, ok := e.(types.String); ok && !s.IsNull() {
				idStrings = append(idStrings, s.ValueString())
			}
		}
		if len(idStrings) > 0 {
			queryValues["id"] = idStrings
		}
	} else if !data.ID.IsNull() {
		queryValues.Set("id", data.ID.ValueString())
	}
	if !data.Names.IsNull() && len(data.Names.Elements()) > 0 {
		nameStrings := make([]string, 0, len(data.Names.Elements()))
		for _, e := range data.Names.Elements() {
			if s, ok := e.(types.String); ok && !s.IsNull() {
				nameStrings = append(nameStrings, s.ValueString())
			}
		}
		if len(nameStrings) > 0 {
			queryValues["name"] = nameStrings
		}
	} else if !data.Name.IsNull() {
		queryValues.Set("name", data.Name.ValueString())
	}
	if len(queryValues) > 0 {
		request.SetQueryParamsFromValues(queryValues)
	}

	if !data.Category.IsNull() {
		request.SetQueryParam("category", data.Category.ValueString())
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

	var result resource.TemplatesListAPIModel
	response, err := request.SetResult(&result).Get(resource.TemplatesEndpoint)

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

func (m *TemplatesDataSourceModel) FromAPIModel(ctx context.Context, apiModel resource.TemplatesListAPIModel) diag.Diagnostics {
	var diags diag.Diagnostics

	// Convert templates list
	templates := make([]types.Object, len(apiModel.Items))
	templateAttrTypes := map[string]attr.Type{
		"id":               types.StringType,
		"name":             types.StringType,
		"description":      types.StringType,
		"category":         types.StringType,
		"data_source_type": types.StringType,
		"is_custom":        types.BoolType,
		"created_at":       types.StringType,
		"updated_at":       types.StringType,
	}

	for i, template := range apiModel.Items {
		templateAttrs := map[string]attr.Value{
			"id":               types.StringValue(template.ID),
			"name":             types.StringValue(template.Name),
			"category":         types.StringValue(template.Category),
			"data_source_type": types.StringValue(template.DataSourceType),
			"is_custom":        types.BoolValue(template.IsCustom),
		}

		// Handle description: if pointer is nil, set to null; otherwise use the value (even if empty string)
		if template.Description != nil {
			templateAttrs["description"] = types.StringValue(*template.Description)
		} else {
			templateAttrs["description"] = types.StringNull()
		}

		if template.CreatedAt != "" {
			templateAttrs["created_at"] = types.StringValue(template.CreatedAt)
		} else {
			templateAttrs["created_at"] = types.StringNull()
		}

		if template.UpdatedAt != "" {
			templateAttrs["updated_at"] = types.StringValue(template.UpdatedAt)
		} else {
			templateAttrs["updated_at"] = types.StringNull()
		}

		templateObj, templateDiags := types.ObjectValue(templateAttrTypes, templateAttrs)
		diags.Append(templateDiags...)
		if !diags.HasError() {
			templates[i] = templateObj
		}
	}

	templatesList, listDiags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: templateAttrTypes}, templates)
	diags.Append(listDiags...)
	if !diags.HasError() {
		m.Templates = templatesList
	} else {
		m.Templates = types.ListNull(types.ObjectType{AttrTypes: templateAttrTypes})
	}

	m.Offset = types.Int64Value(int64(apiModel.Offset))
	m.PageSize = types.Int64Value(int64(apiModel.PageSize))

	return diags
}
