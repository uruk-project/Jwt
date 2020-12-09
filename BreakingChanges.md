## Breaking changes in v2.0
The v2.0 introduces a lot of breaking changes with the version 1.X. 

### JWT parsing
The method `TokenValidationResult JwtReader.TryReadToken(string token, TokenValidationPolicy policy)` has been replaced 
by the method `Jwt.TryParse(string token, TokenValidationPolicy policy, out Jwt jwt)`. 
Instead of returning a `TokenValidationResult`, the result is simply a boolean. The error can be found in the `Error` property of the Jwt.
The `Jwt`object MUST be disposed when consumed. Lake of dispose may produce an impact on the GC.

The `TokenValidationPolicy` & the `TokenValidationPolicyBuilder` have also evolved. 
For defining the triplet [issuer ; signature key ; signature algorithm], use the method `TokenValidationPolicyBuilder.RequireIssuer(string issuer, Jwk key, SignatureAlgorithm defaultAlgorithm)`.
This allow to validate tokens from multiple issuers, each issuer is linked to the key(s) and the default signature algorithm.
See this [sample](samples/MultiIssuersValidationSample) 

### Jwt Writing
The `JwsDescriptor`, `JweDescriptor`, `PlaintextJweDescriptor` & `BinaryJweDescriptor` have now mandatory parameters instead of properties to set:
* The signing key for `JwsDescriptor`, and the encryption key for the others,
* The signature algorithm for `JwsDescriptor` an the key management algorithm,

### Go further
The [samples](samples) illustrate the different use case: 
