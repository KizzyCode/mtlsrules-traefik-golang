[![License BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

# `mtlsrules-traefik-golang`
This [Traefik-plugin](https://plugins.traefik.io/install) offers additional mTLS access rules to complement Traefik's
mTLS authentication.

Currently supported validation rules are:
- Restrict access to specific CA per router
- Restrict access to specific common names per router
- Restrict access to specific certificate serial numbers per router


## **Important Security Note**
This middleware specifies _optional additional_ rules – meaning: if you don't specify a validation rule, it will not be
performed.

This also means that **if you don't specify a root certificate, the certificate chain will not be validated**. To ensure
your certificate is validated, always either set a `rootCert`, or use either Traefik's `VerifyClientCertIfGiven` or
`RequireAndVerifyClientCert` rules in the mTLS configuration.


## Example Service Configuration
Please note that [mTLS needs to be enabled](https://doc.traefik.io/traefik/https/tls/#client-authentication-mtls) in the
dynamic configuration. If mTLS is enabled, you can configure your `whoami` router to:
- Require mTLS (`traefik.http.routers.whoami.tls.options=mtls@file`)
- Create a new middleware (e.g. `traefik.http.routers.whoami.middlewares=mtls-common-names`)
- Setup a root certificate (e.g.
  `traefik.http.middlewares.mtls-common-names.plugin.mtlsrules.rootCert=/etc/traefik/TestCA.crt`)
- Setup a common name to check against (e.g.
  `traefik.http.middlewares.mtls-common-names.plugin.mtlsrules.commonNames[0]=mTLS Rules Test Client A`)

```yaml
whoami:
    image: traefik/whoami
    labels:
        # Basic traefik config
        - traefik.enable=true
        - traefik.http.routers.whoami.rule=Host(`whoami.invalid`)
        - traefik.http.routers.whoami.tls=true
        # mTLS Rules
        - traefik.http.routers.whoami.tls.options=mtls@file
        - traefik.http.routers.whoami.middlewares=mtls-common-names
        - traefik.http.middlewares.mtls-common-names.plugin.mtlsrules.rootCert=/etc/traefik/TestCA.crt
        - traefik.http.middlewares.mtls-common-names.plugin.mtlsrules.commonNames[0]=mTLS Rules Test Client A
    command:
        - --name=This is resource is only accessible via mTLS
```


## Testing
To run some manual tests, fire up the docker container via the provided [`docker-compose.yml`](./docker-compose.yml).

### Test Client Certificate A (expected valid)
To test that client certificate A is allowed, run:
``` sh
curl -vvv --cert-type P12 --cert .docker/TestClientA.pfx --resolve whoami.invalid:443:127.0.0.1 --insecure https://whoami.invalid
```

### Test Client Certificate A (expected rejected)
To test that client certificate B is validated but rejected, run:
``` sh
curl -vvv --cert-type P12 --cert .docker/TestClientA.pfx --resolve whoami.invalid:443:127.0.0.1 --insecure https://whoami.invalid
```

### Test Invalid Client Certificat3e (expected invalid)
To test that the invalid client certificate does not pass validation, run:
``` sh
curl -vvv --cert-type P12 --cert .docker/TestInvalidClient.pfx --resolve whoami.invalid:443:127.0.0.1 --insecure https://whoami.invalid
```
