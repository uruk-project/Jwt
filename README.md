JSON Web Token  for .Net
===========

Provides support for JWT. 
This library aims to propose performant JWT primitives. 

![.NET Core CI/CD](https://github.com/uruk-project/Jwt/workflows/.NET%20Core%20CI/CD/badge.svg) 

## Packages
Package	| Version | 	Description
--|--|--
JsonWebToken |   [![NuGet](https://img.shields.io/nuget/v/JsonWebToken.svg?style=flat)](https://www.nuget.org/packages/JsonWebToken/) |	Nuget	package with JWT primitives. Use this package for common JWT usages.
JsonWebToken.OAuth2 |   [![NuGet](https://img.shields.io/nuget/v/JsonWebToken.OAuth2.svg?style=flat)](https://www.nuget.org/packages/JsonWebToken.OAuth2/) |	Nuget	package with [OAuth2](https://datatracker.ietf.org/wg/oauth/documents/) & [OIDC](https://openid.net/developers/specs/) primitives. Use this package for more specifics usages like [ID tokens](https://openid.net/specs/openid-connect-core-1_0.html#IDToken), [access tokens](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-11), [state parameter](https://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-09), [software statement](https://tools.ietf.org/html/rfc7591#section-2.3), [vector of trust](https://tools.ietf.org/html/rfc8485) or [client assertion](https://tools.ietf.org/html/rfc7523#section-2.2).
JsonWebToken.SecurityEventTokens |   [![NuGet](https://img.shields.io/nuget/v/JsonWebToken.SecurityEventTokens.svg?style=flat)](https://www.nuget.org/packages/JsonWebToken.SecurityEventTokens/) |	Nuget	package with specifics [SecEvents](https://tools.ietf.org/html/rfc8417) primitives.
JsonWebToken.KeyVault | [![NuGet](https://img.shields.io/nuget/v/JsonWebToken.KeyVault.svg?style=flat)](https://www.nuget.org/packages/JsonWebToken.KeyVault/) |	Nuget	package with Key Vault support. Use this package if your keys are stored into an Azure KeyVault.

## Installation
Install the [JsonWebToken NuGet Package](https://www.nuget.org/packages/JsonWebToken/).

### Package Manager Console
```
Install-Package JsonWebToken -Version 1.9.3
```

For the latest beta version:
```
Install-Package JsonWebToken -Version 2.0.0-beta.4
```
### .NET CLI
```
dotnet add package JsonWebToken
```
## Usage
See the [samples](https://github.com/ycrumeyrolle/Jwt/tree/master/samples) for more details.

The `Jwt` class is used for reading and validating tokens:
```
if(Jwt.TryParse("eyJhbGc[...]sWBedk", policy, out var jwt)
{
  // Use the JWT
  // ...
  // Then dispose the object
  jwt.Dispose();
}
```

The `JwtWriter` is used for writing tokens:
```
var writer = new JwtWriter();
var token = writer.WriteTokenString(descriptor);
```
### JWT validation
```
var key = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");
var policy = new TokenValidationPolicyBuilder()
                .RequireIssuer("https://idp.example.com/", key, SignatureAlgorithm.HmacSha256)
                .RequireAudience("636C69656E745F6964")
                .Build();

if (Jwt.TryParse("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MDAwMDcyMDAsImlhdCI6MjAwMDAwNzIwMCwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiYXVkIjoiNjM2QzY5NjU2RTc0NUY2OTY0In0.YrrT1Ddp1ampsDd2GwYZoTz_bUnLt_h--f16wsWBedk", policy, out Jwt jwt))
{
    Console.WriteLine("The token is " + jwt);
}
else
{
    Console.WriteLine("Failed to read the token. Reason: " + Environment.NewLine + jwt.Error.Status);
}

// Do not forget to dispose the Jwt, or you may suffer of GC impacts
jwt.Dispose();
````

### JWT creation
````
// Creates a symmetric key defined for the 'HS256' algorithm
var signingKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");

// Creates a JWS descriptor with all its properties
var descriptor = new JwsDescriptor(signingKey, SignatureAlgorithm.HmacSha256)
{
    Payload = new JwtPayload
    {
        { Claims.Iat, EpochTime.UtcNow },
        { Claims.Exp, EpochTime.UtcNow + EpochTime.OneHour },
        { Claims.Iss, "https://idp.example.com/" },
        { Claims.Aud, "636C69656E745F6964" }
    }
};
   

// Generates the UTF-8 string representation of the JWT
var writer = new JwtWriter();
var token = writer.WriteTokenString(descriptor);

Console.WriteLine("The JWT is:");
Console.WriteLine(descriptor);
Console.WriteLine();
Console.WriteLine("Its compact form is:");
Console.WriteLine(token);
````
## Performances
See [benchmarks](Benchmark.md) for details. 
This library is about **12x** faster than the Microsoft.IdentityModel.Tokens.Jwt when decoding and validating the token, with less than **5-10% memory allocation**. (**6x** faster including signature validation or for encrypted tokens)

In case of invalid token, is is about **25x** faster for detecting an invalid signature.

It is about **4x faster** when writing a JWS of common size, with less than **1-2% memory allocation**. (3x faster including signature generation, 5x faster for encrypted tokens)

The main reason of the efficiency of this library is the usage of the new API provided in .NET Core 2.0, 2.1 & 3.0, like the new Span API, the new JSON API, and the intrisics SIMD API.

## Supported JWT
* [Signed JWT (JWS)](https://tools.ietf.org/html/rfc7515). See [sample](https://github.com/ycrumeyrolle/Jwt/blob/master/samples/JwsCreationSample/Program.cs).
* [Nested encrypted JWT (JWE)](https://tools.ietf.org/html/rfc7519#appendix-A.2): JWE with JWS as payload (know as JWE or Encrypted JWS). See [sample](https://github.com/ycrumeyrolle/Jwt/blob/master/samples/JweCreationSample/Program.cs).
* [Plaintext JWE](https://tools.ietf.org/html/rfc7519#appendix-A.1): JWE with plaintext as payload. See [sample](https://github.com/ycrumeyrolle/Jwt/blob/master/samples/PlaintextJwtCreationSample/Program.cs).
* Binary JWE: JWE with binary as payload. See [sample](https://github.com/ycrumeyrolle/Jwt/blob/master/samples/BinaryJwtCreationSample/Program.cs).
* [Compressed JWE](https://tools.ietf.org/html/rfc7516#section-4.1.3) : JWE compressed with Deflate compression algorithm.
* [Unsecure JWT](https://tools.ietf.org/html/rfc7515#appendix-A.5): JWS without signature. See [sample](https://github.com/ycrumeyrolle/Jwt/blob/master/samples/UnsecureJwtCreationSample/Program.cs).

## Supported algorithms
### JWS signing algorithms
| "alg" Param Value | Digital Signature or MAC Algorithm        | Target Framework   
|--------------|------------------------------------------------|-
| HS256        | HMAC using SHA-256                             | netstandard2.0
| HS384        | HMAC using SHA-384                             | netstandard2.0
| HS512        | HMAC using SHA-512                             | netstandard2.0
| RS256        | RSASSA-PKCS1-v1_5 using SHA-256                | netstandard2.0
| RS384        | RSASSA-PKCS1-v1_5 using SHA-384                | netstandard2.0
| RS512        | RSASSA-PKCS1-v1_5 using SHA-512                | netstandard2.0
| ES256        | ECDSA using curve P-256 and SHA-256                  | netcoreapp2.1
| ES384        | ECDSA using curve P-384 and SHA-384                  | netcoreapp2.1
| ES512        | ECDSA using curve P-521 and SHA-512                  | netcoreapp2.1
| ES256K       | ECDSA using curve secp256k1  and SHA-256             | netcoreapp2.1 (not available on MacOS)
| PS256        | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 | netstandard2.0
| PS384        | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 | netstandard2.0
| PS512        | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 | netstandard2.0
| none         | No digital signature or MAC performed          | netstandard2.0

### JWE encryption algorithms
| "enc" Param Value | Content Encryption Algorithm | Target Framework                           
|---------------|----------------------------------|-                           
| A128CBC-HS256 | AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm | netstandard2.0
| A192CBC-HS384 | AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm | netstandard2.0
| A256CBC-HS512 | AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm | netstandard2.0
| A128GCM       | AES GCM using 128-bit key                                   | netcoreapp3.0
| A192GCM       | AES GCM using 192-bit key                                   | netcoreapp3.0
| A256GCM       | AES GCM using 256-bit key                                   | netcoreapp3.0

### JWE content encryption key algorithm
| "alg" Param Value  | Key Management Algorithm                                                      | Target Framework
|--------------------|-------------------------------------------------------------------------------|-
| RSA1_5             | RSAES-PKCS1-v1_5                                                              | netstandard2.0
| RSA-OAEP           | RSAES OAEP using default parameters                                           | netstandard2.0
| RSA-OAEP-256       | RSAES OAEP using SHA-256 and MGF1 with SHA-256                                | netstandard2.0
| A128KW             | AES Key Wrap with default initial value using 128-bit key                     | netstandard2.0
| A192KW             | AES Key Wrap with default initial value using 192-bit key                     | netstandard2.0
| A256KW             | AES Key Wrap with default initial value using 256-bit key                     | netstandard2.0
| dir                | Direct use of a shared symmetric key as the CEK                               | netstandard2.0
| ECDH-ES            | Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF | netcoreapp2.1
| ECDH-ES+A128KW     | ECDH-ES using Concat KDF and CEK wrapped with "A128KW"                        | netcoreapp2.1
| ECDH-ES+A192KW     | ECDH-ES using Concat KDF and CEK wrapped with "A192KW"                        | netcoreapp2.1
| ECDH-ES+A256KW     | ECDH-ES using Concat KDF and CEK wrapped with "A256KW"                        | netcoreapp2.1
| A128GCMKW          | Key wrapping with AES GCM using 128-bit key                                   | netcoreapp3.0
| A192GCMKW          | Key wrapping with AES GCM using 192-bit key                                   | netcoreapp3.0
| A256GCMKW          | Key wrapping with AES GCM using 256-bit key                                   | netcoreapp3.0
| PBES2-HS256+A128KW | PBES2 with HMAC SHA-256 and "A128KW" wrapping                                 | netstandard2.0
| PBES2-HS384+A192KW | PBES2 with HMAC SHA-384 and "A192KW" wrapping                                 | netstandard2.0
| PBES2-HS512+A256KW | PBES2 with HMAC SHA-512 and "A256KW" wrapping                                 | netstandard2.0
