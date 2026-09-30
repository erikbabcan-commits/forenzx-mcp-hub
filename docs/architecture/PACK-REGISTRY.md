# ForenZX v5 pack registry

Each pack lives under `packs/<id>/manifest.json` and declares supported platforms, input types, capabilities, container image and an exact image digest.

A digest must match:

```text
^sha256:[a-f0-9]{64}$
```

The registry additionally rejects obvious placeholder patterns. Invalid/placeholder packs are visible in the dashboard but disabled for execution.

## Digest override

The dashboard action **Set real digest** stores the verified value in SQLite table `pack_overrides`. This keeps the source pack directory read-only in container deployments.

## Docker verification

RepoDigest values such as:

```text
ghcr.io/vendor/image@sha256:0123...
```

are normalized to:

```text
sha256:0123...
```

and compared to the pin. No short image ID fallback is accepted.
