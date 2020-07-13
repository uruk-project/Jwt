﻿using System;
using JsonWebToken;

namespace JweCreationSample
{
    class Program
    {
        static void Main()
        {
            // Creates a symmetric key defined for the 'HS256' algorithm
            var signatureKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");

            // Creates a symmetric key for encryption
            var encryptionKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4T");

            // Creates a JWE descriptor with all its properties
            var descriptor = new JweDescriptor<JwsDescriptor>()
            {
                EncryptionKey = encryptionKey,
                EncryptionAlgorithm = EncryptionAlgorithm.Aes128CbcHmacSha256,
                Algorithm = KeyManagementAlgorithm.Aes128KW,
                Payload = new JwsDescriptor
                {
                    SigningKey = signatureKey,
                    Algorithm = SignatureAlgorithm.HmacSha256,
                    IssuedAt = DateTime.UtcNow,
                    ExpirationTime = DateTime.UtcNow.AddHours(1),
                    Issuer = "https://idp.example.com/",
                    Audience = "636C69656E745F6964"
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
