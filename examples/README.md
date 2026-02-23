# Example configurations

These examples are used by [terraform-plugin-docs](https://github.com/hashicorp/terraform-plugin-docs) to generate the **Example Usage** sections in the provider documentation.

- **resources/** — One folder per resource (e.g. `templates/`, `rules/`, `lifecycle_policies/`) with `resource.tf` and, where applicable, `import.sh`.
- **datasources/** — One folder per data source with `resource.tf` (the data source block and optional outputs).

**Regenerating docs:** Run from the **provider repo root** (`terraform-provider-unifiedpolicy/`) so the tool can find these paths:

```bash
cd terraform-provider-unifiedpolicy
go generate ./...
```

If docs are generated from another directory, the Example Usage sections may be empty because the `tffile` paths in the templates are resolved relative to the current working directory.
