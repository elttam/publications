# Jupyter Enterprise Gateway Advisories

Three vulnerabilities discovered in [Jupyter Enterprise Gateway](https://github.com/jupyter-server/enterprise_gateway), all fixed in `3.3.0`. See also the [blog post](https://www.elttam.com/resources) and [Nuclei templates](./nuclei/).

| GHSA | CVE | Summary | Nuclei |
|------|-----|---------|--------|
| [GHSA-f49j-v924-fx9w](./GHSA-f49j-v924-fx9w.ssti.md) | CVE-2026-44181 | Jinja2 SSTI resulting in Remote Code Execution | [template](./nuclei/jupyter-enterprise-gateway-ssti.yaml) |
| [GHSA-cfw7-6c5v-2wjq](./GHSA-cfw7-6c5v-2wjq.manifest-injection.md) | CVE-2026-44182 | Kubernetes Manifest Injection | [template](./nuclei/jupyter-enterprise-gateway-manifest-injection.yaml) |
| [GHSA-chq7-94j8-cj28](./GHSA-chq7-94j8-cj28.enforce_prohibited_ids-bypass.md) | CVE-2026-44180 | `enforce_prohibited_ids` UID/GID Bypass | [template](./nuclei/jupyter-enterprise-gateway-id-bypass.yaml) |
