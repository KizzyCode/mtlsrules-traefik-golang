[![License BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

# `mtlsrules-traefik-golang`
This [Traefik-plugin](https://plugins.traefik.io/install) to complements Traefik's mTLS authentication by allowing you
to restrict access for valid certificates to specific subset common names (CN).


## ⚠️ **HAZMAT - Important Security Note** ⚠️
The middleware does not verify the mTLS certificate chain. You __MUST__ to ensure that the certificate has already been
validated by Traefik using `VerifyClientCertIfGiven` or `RequireAndVerifyClientCert` in the mTLS configuration, or by
another middleware upfront.


## Example Service Configuration
Please note that [mTLS needs to be enabled](https://doc.traefik.io/traefik/https/tls/#client-authentication-mtls) in the
dynamic configuration. If mTLS is enabled, you can configure your `whoami` router to:
- Require mTLS (`traefik.http.routers.whoami.tls.options=mtls@file`)
- Create a new middleware (e.g. `traefik.http.routers.whoami.middlewares.mtls-common-names`)
- Setup a common name rule to match against:
  ```
  # Regex for a single name
  traefik.http.middlewares.mtls-common-names.plugin.mtlsrules.cn=Regex(`mTLS Rules Test Client A`)
  ```

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
        - traefik.http.routers.whoami.middlewares.mtls-cn
        - traefik.http.middlewares.mtls-cn.plugin.mtlsrules.cn=Regex(`mTLS Rules Test Client A`)
    command:
        - --name=This is resource is only accessible via mTLS
```


## Testing
To run some manual tests, fire up the docker container via the provided [`docker-compose.yml`](./docker-compose.yml).

### Test Client Certificate A (expected valid)
To test that client certificate A is allowed, run:
``` sh
curl -vvv --cert-type P12 --cert .assets/TestClientA.pfx \
  --resolve whoami.invalid:443:127.0.0.1 --insecure https://whoami.invalid
```

### Test Client Certificate A (expected rejected)
To test that client certificate B is validated but rejected, run:
``` sh
curl -vvv --cert-type P12 --cert .assets/TestClientA.pfx \
  --resolve whoami.invalid:443:127.0.0.1 --insecure https://whoami.invalid
```

### Test Invalid Client Certificate (expected invalid)
To test that the invalid client certificate does not pass validation, run:
``` sh
curl -vvv --cert-type P12 --cert .assets/TestInvalidClient.pfx \
  --resolve whoami.invalid:443:127.0.0.1 --insecure https://whoami.invalid
```
