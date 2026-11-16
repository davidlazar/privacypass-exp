This readme is written by a human.

We (Ryker, Sebastian, and I) built this demo of Privacy Pass during a Recurse Pairing Jam. 

Privacy Pass ([RFC](https://www.rfc-editor.org/rfc/rfc9576.html), [paper](https://petsymposium.org/popets/2018/popets-2018-0026.php))
is a way for users to anonymously authenticate to services.

The *publicly verifiable tokens* version of the protocol used in this repo
builds on a mathematical property of RSA that lets someone with an RSA
private key sign a message without learning the message they signed.
Known as [blind RSA signatures](https://en.wikipedia.org/wiki/Blind_signature#Blind_RSA_signatures).

In our demo, the issuer server (main.go) has an RSA key which produces
blinded signatures for users who authenticate over OAuth.
The users unblind the signatures to produce authentication *tokens*
that are unlinkable to the OAuth user who requested them.
The *wallet* (a static HTML file) stores tokens for the user in
their browser's local storage.

Other apps (like our demo/origin/main.go) that want to support anonymous
logins can request a token from the user's wallet (via `postMessage`)
which can then be verified using the issuer's RSA public key.

The code is the result of ~20 turns of Opus 5.5 with human review.

### Future work

- Key rotation
- Rate-limiting
- Think about whether Privacy Pass makes sense as a way to authenticate requests to an LLM API.

### Deploy on Disco

[Disco](https://disco.cloud/) is a convenient way to deploy the experiment.
To deploy the issuer from this directory:

```
disco projects:add --name privacypass-issuer --domain privacypass-issuer.example.com
disco env:set BASE_URL=https://privacypass-issuer.example.com/ OAUTH_CLIENT_ID=xxx OAUTH_CLIENT_SECRET=xxx OAUTH_AUTH_URL=https://example.com/oauth/authorize OAUTH_TOKEN_URL=https://example.com/oauth/token OAUTH_USERINFO_URL=https://example.com/api/v1/profiles/me --project privacypass-issuer
disco deploy --dir . --project privacypass-issuer
```

Next we deploy a demo app that uses **Login With Privacy Pass**.
We can deploy from the same directory by setting `DISCO_JSON_PATH`:

```
disco projects:add --name privacypass-demo --domain privacypass-demo.example.com
disco env:set DISCO_JSON_PATH=demo/origin/disco.json ISSUER_URL=https://privacypass-issuer.example.com --project privacypass-demo
disco deploy --dir . --project privacypass-demo
```
