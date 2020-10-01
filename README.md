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
