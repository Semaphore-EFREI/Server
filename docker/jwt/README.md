# JWT Keys (Local Dev)

Generate a local RSA keypair for JWT signing/verification:

```
mkdir -p docker/jwt
openssl genrsa -out docker/jwt/private.pem 2048
openssl rsa -in docker/jwt/private.pem -pubout -out docker/jwt/public.pem
```

These keys are for local development only. Do not use in production.
