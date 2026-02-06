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

var _ datasource.DataSource = &RulesDataSource{}

func NewRulesDataSource() datasource.DataSource {
	return &RulesDataSource{}
}

type RulesDataSource struct {
	ProviderData util.ProviderMetadata
}

type RulesDataSourceModel struct {
	ID                 types.String `tfsdk:"id"`
	IDs                types.List   `tfsdk:"ids"`
	Name               types.String `tfsdk:"name"`
	Names              types.List   `tfsdk:"names"`
	ScannerTypes       types.List   `tfsdk:"scanner_types"`
	TemplateDataSource types.String `tfsdk:"template_data_source"`
	TemplateCategory   types.String `tfsdk:"template_category"`
	Expand             types.String `tfsdk:"expand"`
	Page               types.Int64  `tfsdk:"page"`
	Limit              types.Int64  `tfsdk:"limit"`
	SortBy             types.String `tfsdk:"sort_by"`
	SortOrder          types.String `tfsdk:"sort_order"`
	Rules              types.List   `tfsdk:"rules"`
	Offset             types.Int64  `tfsdk:"offset"`
	PageSize           types.Int64  `tfsdk:"page_size"`
}

func (d *RulesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_rules"
}

func (d *RulesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Returns a list of Unified Policy rules with support for filtering, pagination, and sorting. " +
			"This datasource can be used to query rules by IDs, names, scanner types, template data source, template category, and more.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Filter by a single rule ID. Sent as query parameter `id`.",
				Optional:    true,
			},
			"ids": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "Filter by rule IDs. Multiple IDs are sent as repeated `id` query parameters (e.g. ?id=rule-1&id=rule-2).",
				Optional:    true,
			},
			"name": schema.StringAttribute{
				Description: "Filter by a single rule name. Sent as query parameter `name`.",
				Optional:    true,
			},
			"names": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "Filter by rule names. Multiple names are sent as repeated `name` query parameters.",
				Optional:    true,
			},
			"scanner_types": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "Filter by scanner types (e.g., 'sca', 'secrets'). Sent as repeated query parameters.",
				Optional:    true,
			},
			"template_data_source": schema.StringAttribute{
				Description: "Filter by template data source (e.g., 'xray', 'catalog').",
				Optional:    true,
			},
			"template_category": schema.StringAttribute{
				Description: "Filter by template category (e.g., 'security', 'quality').",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("security", "legal", "operational", "quality", "audit", "workflow"),
				},
			},
			"expand": schema.StringAttribute{
				Description: "Expand related fields, such as 'template'.",
				Optional:    true,
			},
			"page": schema.Int64Attribute{
				Description: "Page offset (default: 0).",
				Optional:    true,
			},
			"limit": schema.Int64Attribute{
				Description: "Items per page (1-1000, default: 100).",
				Optional:    true,
			},
			"sort_by": schema.StringAttribute{
				Description: "Sort field: 'name', 'created_at'.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("name", "created_at"),
				},
			},
			"sort_order": schema.StringAttribute{
				Description: "Sort direction: 'asc' or 'desc'.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("asc", "desc"),
				},
			},
			"rules": schema.ListNestedAttribute{
				Description: "List of rules returned by the API.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The ID of the rule.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "The rule name.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "Free-text description of the rule purpose.",
							Computed:    true,
						},
						"is_custom": schema.BoolAttribute{
							Description: "Whether the rule is user-defined (true) or predefined (false).",
							Computed:    true,
						},
						"template_id": schema.StringAttribute{
							Description: "The ID of the template the rule is based on.",
							Computed:    true,
						},
						"parameters": schema.ListNestedAttribute{
							Description: "Array of parameter name/value pairs.",
							Computed:    true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Description: "Parameter name.",
										Computed:    true,
									},
									"value": schema.StringAttribute{
										Description: "Parameter value.",
										Computed:    true,
									},
								},
							},
						},
						"created_at": schema.StringAttribute{
							Description: "Timestamp when the rule was created.",
							Computed:    true,
						},
						"updated_at": schema.StringAttribute{
							Description: "Timestamp when the rule was last updated.",
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

func (d *RulesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (d *RulesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data RulesDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := d.ProviderData.Client.R().SetContext(ctx)

	// Build multi-value query params (id, name, scanner_types) in one Values so all can be sent (same pattern as templates)
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
	if !data.ScannerTypes.IsNull() && len(data.ScannerTypes.Elements()) > 0 {
		scannerStrings := make([]string, 0, len(data.ScannerTypes.Elements()))
		for _, e := range data.ScannerTypes.Elements() {
			if s, ok := e.(types.String); ok && !s.IsNull() {
				scannerStrings = append(scannerStrings, s.ValueString())
			}
		}
		if len(scannerStrings) > 0 {
			queryValues["scanner_types"] = scannerStrings
		}
	}
	if len(queryValues) > 0 {
		request.SetQueryParamsFromValues(queryValues)
	}

	if !data.TemplateDataSource.IsNull() {
		request.SetQueryParam("template_data_source", data.TemplateDataSource.ValueString())
	}

	if !data.TemplateCategory.IsNull() {
		request.SetQueryParam("template_category", data.TemplateCategory.ValueString())
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

	var result resource.RulesListAPIModel
	response, err := request.SetResult(&result).Get(resource.RulesEndpoint)

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

// ruleListItemAttrTypes is used for converting list items to Terraform types.
var ruleListItemAttrTypes = map[string]attr.Type{
	"id":          types.StringType,
	"name":        types.StringType,
	"description": types.StringType,
	"is_custom":   types.BoolType,
	"template_id": types.StringType,
	"parameters":  types.ListType{ElemType: types.ObjectType{AttrTypes: map[string]attr.Type{"name": types.StringType, "value": types.StringType}}},
	"created_at":  types.StringType,
	"updated_at":  types.StringType,
}

func (m *RulesDataSourceModel) FromAPIModel(ctx context.Context, apiModel resource.RulesListAPIModel) diag.Diagnostics {
	var diags diag.Diagnostics

	rules := make([]types.Object, len(apiModel.Items))
	paramAttrTypes := map[string]attr.Type{
		"name":  types.StringType,
		"value": types.StringType,
	}

	for i, rule := range apiModel.Items {
		// Parameters list for this rule
		paramValues := make([]attr.Value, len(rule.Parameters))
		for j, p := range rule.Parameters {
			paramObj := types.ObjectValueMust(paramAttrTypes, map[string]attr.Value{
				"name":  types.StringValue(p.Name),
				"value": types.StringValue(p.Value),
			})
			paramValues[j] = paramObj
		}
		parametersList, paramDiags := types.ListValue(types.ObjectType{AttrTypes: paramAttrTypes}, paramValues)
		diags.Append(paramDiags...)
		if diags.HasError() {
			break
		}

		description := types.StringNull()
		if rule.Description != "" {
			description = types.StringValue(rule.Description)
		}
		createdAt := types.StringNull()
		if rule.CreatedAt != "" {
			createdAt = types.StringValue(rule.CreatedAt)
		}
		updatedAt := types.StringNull()
		if rule.UpdatedAt != "" {
			updatedAt = types.StringValue(rule.UpdatedAt)
		}

		ruleAttrs := map[string]attr.Value{
			"id":          types.StringValue(rule.ID),
			"name":        types.StringValue(rule.Name),
			"description": description,
			"is_custom":   types.BoolValue(rule.IsCustom),
			"template_id": types.StringValue(rule.TemplateID),
			"parameters":  parametersList,
			"created_at":  createdAt,
			"updated_at":  updatedAt,
		}

		ruleObj, ruleDiags := types.ObjectValue(ruleListItemAttrTypes, ruleAttrs)
		diags.Append(ruleDiags...)
		if !diags.HasError() {
			rules[i] = ruleObj
		}
	}

	rulesList, listDiags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: ruleListItemAttrTypes}, rules)
	diags.Append(listDiags...)
	if !diags.HasError() {
		m.Rules = rulesList
	} else {
		m.Rules = types.ListNull(types.ObjectType{AttrTypes: ruleListItemAttrTypes})
	}

	m.Offset = types.Int64Value(int64(apiModel.Offset))
	m.PageSize = types.Int64Value(int64(apiModel.PageSize))

	return diags
}
