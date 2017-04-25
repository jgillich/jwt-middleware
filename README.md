# GO JWT Middleware

A middleware that will check that a [JWT](http://jwt.io/) is sent on the
`Authorization` header and will then set the content of the JWT into the `user`
variable of the request.

This module lets you authenticate HTTP requests using JWT tokens in your Go
Programming Language applications. JWTs are typically used to protect API
endpoints, and are often issued using OpenID Connect.

## Key Features

* Ability to **check the `Authorization` header for a JWT**
* **Decode the JWT** and set the content of it to the request context

## Installing

````bash
go get github.com/jgillich/jwt-middleware
````

## Using it

You can use `jwtmiddleware` with default `net/http` as follows.

````go
// main.go
package main

import (
  "fmt"
  "net/http"

  "github.com/jgillich/jwt-middleware"
  "github.com/dgrijalva/jwt-go"
  "github.com/gorilla/context"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  claims, err := jwtmiddleware.ClaimsValue(r)
  if err != nil {
    // err is safe to ignore unless CredentialsOptional is set to true
    panic(err)
  }
  fmt.Fprintf(w, "This is an authenticated request")
  fmt.Fprintf(w, "Claim content:\n")
  for k, v := range claims {
    fmt.Fprintf(w, "%s :\t%#v\n", k, v)
  }
})

func main() {
  jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
    ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
      return []byte("My Secret"), nil
    },
    // When set, the middleware verifies that tokens are signed with the specific signing algorithm
    // If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
    // Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
    SigningMethod: jwt.SigningMethodHS256,
  })

  app := jwtMiddleware.Handler(myHandler)
  http.ListenAndServe("0.0.0.0:3000", app)
}
````

You can also use it with Negroni as follows:

````go
// main.go
package main

import (
  "fmt"
  "net/http"

  "github.com/jgillich/jwt-middleware"
  "github.com/urfave/negroni"
  "github.com/dgrijalva/jwt-go"
  "github.com/gorilla/context"
  "github.com/gorilla/mux"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    claims, err := jwtmiddleware.ClaimsValue(r)
    if err != nil {
      // err is safe to ignore unless CredentialsOptional is set to true
      panic(err)
    }
  fmt.Fprintf(w, "This is an authenticated request")
  fmt.Fprintf(w, "Claim content:\n")
  for k, v := range claims {
    fmt.Fprintf(w, "%s :\t%#v\n", k, v)
  }
})

func main() {
  r := mux.NewRouter()

  jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
    ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
      return []byte("My Secret"), nil
    },
    // When set, the middleware verifies that tokens are signed with the specific signing algorithm
    // If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
    // Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
    SigningMethod: jwt.SigningMethodHS256,
  })

  r.Handle("/ping", negroni.New(
    negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
    negroni.Wrap(myHandler),
  ))
  http.Handle("/", r)
  http.ListenAndServe(":3001", nil)
}
````

## Options

````go
type Options struct {
  // The function that will return the Key to validate the JWT.
  // It can be either a shared secret or a public key.
  // Default value: nil
  ValidationKeyGetter jwt.Keyfunc
  // The function that will be called when there's an error validating the token
  // Default value: https://github.com/jgillich/jwt-middleware/blob/master/jwtmiddleware.go#L35
  ErrorHandler errorHandler
  // A boolean indicating if the credentials are required or not
  // Default value: false
  CredentialsOptional bool
  // A function that extracts the token from the request
  // Default: FromAuthHeader (i.e., from Authorization header as bearer token)
  Extractor TokenExtractor
  // Debug flag turns on debugging output
  // Default: false
  Debug bool
  // When set, all requests with the OPTIONS method will use authentication
  // Default: false
  EnableAuthOnOptions bool,
  // When set, the middelware verifies that tokens are signed with the specific signing algorithm
  // If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
  // Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
  // Default: nil
  SigningMethod jwt.SigningMethod
}
````

### Token Extraction

The default value for the `Extractor` option is the `FromAuthHeader`
function which assumes that the JWT will be provided as a bearer token
in an `Authorization` header, i.e.,

```
Authorization: bearer {token}
```

To extract the token from a query string parameter, you can use the
`FromParameter` function, e.g.,

```go
jwtmiddleware.New(jwtmiddleware.Options{
  Extractor: jwtmiddleware.FromParameter("auth_code"),
})
```

In this case, the `FromParameter` function will look for a JWT in the
`auth_code` query parameter.

Or, if you want to allow both, you can use the `FromFirst` function to
try and extract the token first in one way and then in one or more
other ways, e.g.,

```go
jwtmiddleware.New(jwtmiddleware.Options{
  Extractor: jwtmiddleware.FromFirst(jwtmiddleware.FromAuthHeader,
                                     jwtmiddleware.FromParameter("auth_code")),
})
```

## Examples

You can check out working examples in the [examples folder](https://github.com/jgillich/jwt-middleware/tree/master/examples)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE.txt)
file for more info.
