# JSON Web Signature (JWS) using HMAC (Hash-based Message Authentication Code)
A JWS is a JWT that contains an JSON payload and a signature. 

This example illustrates how to create a JWS using HMAC signature.
The issuer and audience must previously share a secret key. 

## Recommandation: 
Use JWS using HMAC only if the issuer and the recipient are the same. This avoid to share a secret. 
A common use case would be to represent the OAuth2 state parameter as a JWS. 
In this case, the JWS is issued by the client application, then retrieved by the same client application. 

## Supported encryption algorithms
 Algorithm | Description        | Key length  
-----------|--------------------|-----------
HS256      | HMAC using SHA-256 | 128 bits                               
HS384      | HMAC using SHA-384 | 192 bits                               
HS512      | HMAC using SHA-512 | 256 bits  

## Example code
```C#
using System;
using JsonWebToken;

namespace JweCreationSample
{
    class Program
    {
        static void Main()
        {
            // Creates the symmetric key defined for the 'HS256' signature algorithm
            var signatureKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HmacSha256);

            // Creates the JWE descriptor 
            // The descriptor sets the 'alg' with value 'HS256'
            Payload = new JwsDescriptor(signatureKey, SignatureAlgorithm.HmacSha256)
            {
                Payload = new JwtPayload
                {
                    // Defines the JWS claims
                    { JwtClaimNames.Iat, EpochTime.UtcNow },
                    { JwtClaimNames.Exp, EpochTime.UtcNow + EpochTime.OneHour },
                    { JwtClaimNames.Iss, "https://idp.example.com/" },
                    { JwtClaimNames.Aud, "636C69656E745F6964" }
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
        }
    }
}
```
## Output
```JSON
The JWT is:
{
  "alg": "HS256",
  "kid": "S228msQcI9PXHPCQbEkAx3QmasUIhXbdpLUYeQnLxqI"
}
.
{
  "iat": 1606420476,
  "exp": 1606424076,
  "iss": "https://idp.example.com/",
  "aud": "636C69656E745F6964"
}

Its compact form is:
eyJhbGciOiJIUzI1NiIsImtpZCI6IlMyMjhtc1FjSTlQWEhQQ1FiRWtBeDNRbWFzVUloWGJkcExVWWVRbkx4cUkifQ.eyJpYXQiOjE2MDY0MjA0NzYsImV4cCI6MTYwNjQyNDA3NiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiYXVkIjoiNjM2QzY5NjU2RTc0NUY2OTY0In0.kmZs22nzWsFuwhotxG6hE2XTSF7ndLki8EuAuI-9H8o
```