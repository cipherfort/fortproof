# Your rules for the Compose stack

Files placed here replace the defaults shipped in the image, one for one. Use the same paths as the repository,
for example `config/trusted-producers.yaml` or `config/profiles/<profile>/classification.yaml`, and only add the files
you change. The stack mounts this directory at `AAP_RULES_DIR`; restart it to load changes:

```bash
docker compose -f deploy/compose/compose.yaml up -d --force-recreate migrate api worker
```

`aap pipelines approve` writes here when run with `AAP_RULES_DIR=deploy/compose/rules`, and `aap config check`
shows which files come from here. See [Configure](../../../docs/configure/index.md).
