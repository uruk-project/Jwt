JSON Web Token  for .Net
===========

Provides support for JWT. 
This library aims to propose performant JWT primitives. 

[![Build Status](https://yanncrumeyrolle.visualstudio.com/ycrumeyrolle/_apis/build/status/ycrumeyrolle.Jwt)](https://yanncrumeyrolle.visualstudio.com/ycrumeyrolle/_build/latest?definitionId=3)

 [![CodeFactor](https://www.codefactor.io/repository/github/ycrumeyrolle/jwt/badge)](https://www.codefactor.io/repository/github/ycrumeyrolle/jwt)
 
[![NuGet](https://img.shields.io/nuget/v/JsonWebToken.svg?style=flat)](https://www.nuget.org/packages/JsonWebToken/)

## Versions
Current version - [0.3.1](https://www.nuget.org/packages/JsonWebToken/)

## Usage
### JWT validation
````
    var key = new SymmetricJwk { K = "R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU" };
    var validationParameters = new TokenValidationBuilder()
				   .RequireSignature(key)
                                   .RequireAudience("valid_audience>")
				   .RequireIssuer("<valid_issuer>")
				   .Build()

    using (var reader = new JsonWebTokenReader())
    {
      var result = _reader.TryReadToken("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI3NTZFNjk3MTc1NjUyMDY5NjQ2NTZFNzQ2OTY2Njk2NTcyIiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiaWF0IjoxNTA4MTg0ODQ1LCJhdWQiOiI2MzZDNjk2NTZFNzQ1RjY5NjQiLCJleHAiOjE2MjgxODQ4NDV9.2U33urP5-MPw1ipbwEP4nqvEqlZiyUG9Hxi8YS_RQVk");
      if (result.Success)
      {
        Console.WriteLine("The token is " + result.Token);
      }
      else
      {      
        Console.WriteLine("Failed to read the token. Reason: " + result.Status);
      }
    }
````

### JWT creation
````
    var descriptor = new JwsDescriptor()
    {
      Key = new SymmetricJwk { K = "R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU", Alg = "HS256" };,
      ExpirationTime = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc),
      IssuedAt = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc),
      Issuer = "https://idp.example.com/",
      Audience = "636C69656E745F6964"
    };

    using (var writer = new JsonWebTokenWriter())
    {
      string token = writer.WriteToken(descriptor);
    }
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
| "alg" Param Value | Digital Signature or MAC Algorithm        | Target Framework   
|--------------|------------------------------------------------|-
| HS256        | HMAC using SHA-256                             | netstandard2.0
| HS384        | HMAC using SHA-384                             | netstandard2.0
| HS512        | HMAC using SHA-512                             | netstandard2.0
| RS256        | RSASSA-PKCS1-v1_5 using SHA-256                | netstandard2.0
| RS384        | RSASSA-PKCS1-v1_5 using SHA-384                | netstandard2.0
| RS512        | RSASSA-PKCS1-v1_5 using SHA-512                | netstandard2.0
| ES256        | ECDSA using P-256 and SHA-256                  | netcoreapp2.1
| ES384        | ECDSA using P-384 and SHA-384                  | netcoreapp2.1
| ES512        | ECDSA using P-521 and SHA-512                  | netcoreapp2.1
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
| A128GCM       | AES GCM using 128-bit key                                   | netcoreapp2.2 (not ready)
| A192GCM       | AES GCM using 192-bit key                                   | netcoreapp2.2 (not ready)
| A256GCM       | AES GCM using 256-bit key                                   | netcoreapp2.2 (not ready)

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
| A128GCMKW          | Key wrapping with AES GCM using 128-bit key                                   | netcoreapp2.2 (not ready)
| A192GCMKW          | Key wrapping with AES GCM using 192-bit key                                   | netcoreapp2.2 (not ready)
| A256GCMKW          | Key wrapping with AES GCM using 256-bit key                                   | netcoreapp2.2 (not ready)
