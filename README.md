JSON Web Token  for .Net
===========

Provides support for JWT. 
This library aims to propose performant JWT primitives. 

[![Build status](https://ci.appveyor.com/api/projects/status/7lt4w59vy0v60s1b?svg=true)](https://ci.appveyor.com/project/ycrumeyrolle/jwt)
 [![CodeFactor](https://www.codefactor.io/repository/github/ycrumeyrolle/jwt/badge)](https://www.codefactor.io/repository/github/ycrumeyrolle/jwt)

## Versions
Current version - 0.1.0

## Usage
### JWT validation
````
    var key = new SymmetricJwk { K = "R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU" };
    var reader = new JsonWebTokenReader(key);
    var validationParameters = new TokenValidationBuilder()
                                   .RequireAudience("valid_audience>")
				   .RequireSignature(key)
				   .RequireIssuer("<valid_issuer>")
				   .Build()

    var result = _reader.TryReadToken("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI3NTZFNjk3MTc1NjUyMDY5NjQ2NTZFNzQ2OTY2Njk2NTcyIiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiaWF0IjoxNTA4MTg0ODQ1LCJhdWQiOiI2MzZDNjk2NTZFNzQ1RjY5NjQiLCJleHAiOjE2MjgxODQ4NDV9.2U33urP5-MPw1ipbwEP4nqvEqlZiyUG9Hxi8YS_RQVk");
    if (result.Success)
    {
      Console.WriteLine("The token is " + result.Token);
    }
    else
    {      
      Console.WriteLine("Failed to read the token. Reason: " + result.Status);
    }
````

### JWT creation
````
    var writer = new JsonWebTokenWriter();
    
    // Generates a new symmetric key of 256 bits
    var symmetricLKey = SymmetricJwk.GenerateKey(256, "HS256");

    var descriptor = new JwsDescriptor()
    {
      Key = symmetricKey,
      ExpirationTime = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc),
      IssuedAt = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc),
      Issuer = "https://idp.example.com/",
      Audience = "636C69656E745F6964"
    };

    string token = writer.WriteToken(descriptor);
````
## Performances
See [benchmarks](Benchmark.md) for details. 
This library is about **3x** faster than the Microsoft.IdentityModel.Tokens.Jwt when decoding and validating the token, and **2.25x** faster when writing a JWS of common size, with only 1/4 of memory allocation.

The main reason of the speed of this library is the usage of the new API provided in .NET Core 2.0 and .NET Core 2.1.

## Supported JWT
* [JWS](https://tools.ietf.org/html/rfc7515) 
* [Nested JWT](https://tools.ietf.org/html/rfc7519#appendix-A.2): JWE with JWS as payload (know as JWE or Encrypted JWS)
* [Plaintext JWE](https://tools.ietf.org/html/rfc7519#appendix-A.1): JWE with plaintext as payload
* Binary JWE: JWE with binary as payload
* [Unsecure JWT](https://tools.ietf.org/html/rfc7515#appendix-A.5): JWS without signature

## Supported algorithms
### JWS signing algorithms
| "alg" Param Value | Digital Signature or MAC Algorithm        |Implemented
|--------------|-------------------------------                          |---
| HS256        | HMAC using SHA-256                                      | <ul><li> - [x] </li></ul>
| HS384        | HMAC using SHA-384                                      | <ul><li> - [x] </li></ul>
| HS512        | HMAC using SHA-512                                      | <ul><li> - [x] </li></ul>
| RS256        | RSASSA-PKCS1-v1_5 using SHA-256                       | <ul><li> - [x] </li></ul>
| RS384        | RSASSA-PKCS1-v1_5 using SHA-384                       | <ul><li> - [x] </li></ul>
| RS512        | RSASSA-PKCS1-v1_5 using SHA-512                       | <ul><li> - [x] </li></ul>
| ES256        | ECDSA using P-256 and SHA-256                           | <ul><li> - [x] </li></ul>
| ES384        | ECDSA using P-384 and SHA-384                           | <ul><li> - [x] </li></ul>
| ES512        | ECDSA using P-521 and SHA-512                           | <ul><li> - [x] </li></ul>
| PS256        | RSASSA-PSS using SHA-256 and MGF1 with SHA-256     | <ul><li> - [x] </li></ul>
| PS384        | RSASSA-PSS using SHA-384 and MGF1 with SHA-384     | <ul><li> - [x] </li></ul>
| PS512        | RSASSA-PSS using SHA-512 and MGF1 with SHA-512     | <ul><li> - [x] </li></ul>
| none         | No digital signature or MAC performed                      | <ul><li> - [x] </li></ul>

### JWE encryption algorithms
| "enc" Param Value | Content Encryption Algorithm                            |Implemented
|---------------|----------------------------------                           |---
| A128CBC-HS256 | AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm | <ul><li> - [x] </li></ul>
| A192CBC-HS384 | AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm | <ul><li> - [x] </li></ul>
| A256CBC-HS512 | AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm | <ul><li> - [x] </li></ul>
| A128GCM       | AES GCM using 128-bit key                                                 | <ul><li> - [ ] </li></ul>
| A192GCM       | AES GCM using 192-bit key                                                 | <ul><li> - [ ] </li></ul>
| A256GCM       | AES GCM using 256-bit key                                                 | <ul><li> - [ ] </li></ul>

### JWE content encryption key algorithm
| "alg" Param Value  | Key Management Algorithm    | More Header Params                                                    | Implemented 
|--------------------|--------------------|--------                                                                        | ---
| RSA1_5             | RSAES-PKCS1-v1_5                                                              | (none)              | <ul><li> - [x] </li></ul>
| RSA-OAEP           | RSAES OAEP using default parameters                                           | (none)              | <ul><li> - [x] </li></ul>
| RSA-OAEP-256       | RSAES OAEP using SHA-256 and MGF1 with SHA-256                                | (none)              | <ul><li> - [x] </li></ul>
| A128KW             | AES Key Wrap with default initial value using 128-bit key                     | (none)              | <ul><li> - [x] </li></ul>
| A192KW             | AES Key Wrap with default initial value using 192-bit key                     | (none)              | <ul><li> - [x] </li></ul>
| A256KW             | AES Key Wrap with default initial value using 256-bit key                     | (none)              | <ul><li> - [x] </li></ul>
| dir                | Direct use of a shared symmetric key as the CEK                               | (none)              | <ul><li> - [x] </li></ul>
| ECDH-ES            | Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF | "epk", "apu", "apv" | <ul><li> - [X] </li></ul>
| ECDH-ES+A128KW     | ECDH-ES using Concat KDF and CEK wrapped with "A128KW"                        | "epk", "apu", "apv" | <ul><li> - [X] </li></ul>
| ECDH-ES+A192KW     | ECDH-ES using Concat KDF and CEK wrapped with "A192KW"                        | "epk", "apu", "apv" | <ul><li> - [X] </li></ul>
| ECDH-ES+A256KW     | ECDH-ES using Concat KDF and CEK wrapped with "A256KW"                        | "epk", "apu", "apv" | <ul><li> - [X] </li></ul>
| A128GCMKW          | Key wrapping with AES GCM using 128-bit key                                   | "iv", "tag"         | <ul><li> - [ ] </li></ul>
| A192GCMKW          | Key wrapping with AES GCM using 192-bit key                                   | "iv", "tag"         | <ul><li> - [ ] </li></ul>
| A256GCMKW          | Key wrapping with AES GCM using 256-bit key                                   | "iv", "tag"         | <ul><li> - [ ] </li></ul>
| PBES2-HS256+A128KW | PBES2 with HMAC SHA-256 and "A128KW" wrapping                                 | "p2s", "p2c"        | <ul><li> - [ ] </li></ul>
| PBES2-HS384+A192KW | PBES2 with HMAC SHA-384 and "A192KW" wrapping                                 | "p2s", "p2c"        | <ul><li> - [ ] </li></ul>
| PBES2-HS512+A256KW | PBES2 with HMAC SHA-512 and "A256KW" wrapping                                 | "p2s", "p2c"        | <ul><li> - [ ] </li></ul>
