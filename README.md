# Nakedjwts

Used to generate surrogate tokens that can be safely used to configure developer tools.
This can be paired with an oauth proxy like oauth2proxy.


### Running the service
```bash

docker run --rm -ti -v $(pwd):/opt/nakedjwts \
-p 5000:5000 \
naked-jwt-docker-image:latest \
--client-id <IPD_CLIENT_ID> \
--client-secret <IPD_CLIENT_SECRET> \
--surrogate-audience nexus  \
--surrogate-issuer=http://localhost:5000 \
--id-authorize-url=https://login.microsoftonline.com/<IPD_TENANT_IF_AZURE>/oauth2/authorize \
--id-token-url=https://login.microsoftonline.com/<IPD_TENANT_IF_AZURE>/oauth2/token \
--http-port 5000 \
--client-callback-url=http://localhost:5000/oauth2/callback

```


### Creating automation tokens for robot accounts

```bash
docker run --rm -ti -v $(pwd):/opt/nakedjwts \
--entrypoint /usr/local/bin/nakedjwts \
naked-jwt-docker-image:latest \ 
issue  --surrogate-issuer=http://localhost:5000 \
--surrogate-audience=nexus \
--email-claim gitlab-deployer@nowhere.com.au \
--name-claim gitlab-deployer 

```

### Testing timezone settings

- Install the `faketime` utility in order to change the runtime date without affecting the OS.
- Run a test oidc provider like keycloak

```bash
TZ=UTC /usr/local/opt/libfaketime/bin/faketime '2000-12-31 12:00:00' \
go run cmd/nakedjwts/main.go serve \
--timezone "Australia/Sydney" \
--client-id test-client --client-secret 86d9ec3e-0af7-401c-b2ea-579a7dbdbf9f \
--surrogate-audience nexus  --surrogate-issuer=http://localhost:5001 \
--id-authorize-url=http://127.0.0.1.nip.io:8080/auth/realms/test/protocol/openid-connect/auth \
--id-token-url=http://127.0.0.1.nip.io:8080/auth/realms/test/protocol/openid-connect/token \
--http-port 5001 \
--client-callback-url=http://localhost:5001/oauth2/callback

```

```bash
TZ=UTC /usr/local/opt/libfaketime/bin/faketime '2000-12-31 13:00:00' \
go run cmd/nakedjwts/main.go serve \
--timezone "Australia/Sydney" \
--client-id test-client --client-secret 86d9ec3e-0af7-401c-b2ea-579a7dbdbf9f \
--surrogate-audience nexus  --surrogate-issuer=http://localhost:5001 \
--id-authorize-url=http://127.0.0.1.nip.io:8080/auth/realms/test/protocol/openid-connect/auth \
--id-token-url=http://127.0.0.1.nip.io:8080/auth/realms/test/protocol/openid-connect/token \
--http-port 5001 \
--client-callback-url=http://localhost:5001/oauth2/callback

```
