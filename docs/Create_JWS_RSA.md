# JSON Web Signature (JWS) using RSA signature
A JWS is a JWT that contains an JSON payload and a signature. 

This example illustrates how to create a JWS using RSA signature.
The issuer use a RSA private key for signing the token. 
The recipent use a RSA public key for validating the token. 

## Recommandation: 
A key size of 2048 bits or larger is required.

## Supported encryption algorithms
 Algorithm | Description                                    | Key length  
-----------|------------------------------------------------|-----------
RS256      | RSASSA-PKCS1-v1_5 using SHA-256                | 2048+ bits
RS384      | RSASSA-PKCS1-v1_5 using SHA-384                | 2048+ bits
RS512      | RSASSA-PKCS1-v1_5 using SHA-512                | 2048+ bits
PS256      | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 | 2048+ bits
PS384      | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 | 2048+ bits
PS512      | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 | 2048+ bits

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
            // Creates the RSA key defined for the 'PS256' signature algorithm
            var privateKey = RsaJwk.GeneratePrivateKey(SignatureAlgorithm.RsaSsaPssSha256);

            // Creates the JWS descriptor 
            // The descriptor sets the 'alg' with value 'PS256'
            var descriptor = new JwsDescriptor(privateKey, SignatureAlgorithm.RsaSsaPssSha256)
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
  "alg": "PS256",
  "kid": "vGVU7psltqg-iyShw1oZXoTCkZdiaWhSw4-rkAoGKGs"
}
.
{
  "iat": 1606420987,
  "exp": 1606424587,
  "iss": "https://idp.example.com/",
  "aud": "636C69656E745F6964"
}

Its compact form is:
eyJhbGciOiJQUzI1NiIsImtpZCI6InZHVlU3cHNsdHFnLWl5U2h3MW9aWG9UQ2taZGlhV2hTdzQtcmtBb0dLR3MifQ.eyJpYXQiOjE2MDY0MjA5ODcsImV4cCI6MTYwNjQyNDU4NywiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiYXVkIjoiNjM2QzY5NjU2RTc0NUY2OTY0In0.qGDPEWZZxU1Ty3vRmsNVN86RZM_NS4-OnTBX4PtGPIz64upjhB_XKf-CiN2QQFwJXmNiVGQhg2QZA2p1Aqp_fNCRBypCWtvopBFhMm4m_0LxZOPrcG4O_seXQ9_VjHm1VW5Y8rDpep2G9hAFyNkOGVzw1ia-2cfpNH_L5BbDKnJjVFB0isCk9j3qt24iBzP0xAZcYKu856Wps-yhrKv7X_PuZyL3OYVNPF3ILtOUyz4_MvtYVsWPGQXE7XnbTKDqqaKF4cti_mpVhXte7_1qLr8YareJv4uqLL2yvuNfa-tP0q6Wmk3bVmYAVuTiH05nqd7GWMXt86WXgLgLHqlj0g
```