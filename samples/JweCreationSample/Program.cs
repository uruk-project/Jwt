using System;
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
            var descriptor = new JweDescriptor(encryptionKey, KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256)
            {  
                Payload = new JwsDescriptor(signatureKey, SignatureAlgorithm.HmacSha256)
                {
                    Payload = new JwtPayload
                    {
                        // You can use predefined claims
                        { JwtClaimNames.Iat, EpochTime.UtcNow },
                        { JwtClaimNames.Exp, EpochTime.UtcNow + EpochTime.OneHour },
                        { JwtClaimNames.Iss, "https://idp.example.com/" },
                        { JwtClaimNames.Aud, "636C69656E745F6964" },

                        // Or use custom claims 
                        { "value", "ABCEDF" }
                    }
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
