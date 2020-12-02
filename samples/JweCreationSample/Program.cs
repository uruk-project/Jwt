using System;
using JsonWebToken;

namespace JweCreationSample
{
    class Program
    {
        static void Main()
        {
            // Generates the symmetric key for AES encryption with the algorithm 'A256GCMKW'
            var sharedEncryptionKey = SymmetricJwk.GenerateKey(KeyManagementAlgorithm.A256GcmKW);

            // Creates the symmetric key defined for the 'HS256' signature algorithm
            var signatureKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256);

            // Creates the JWE descriptor 
            // The descriptor sets the 'alg' with value 'A256GCMKW' and 'enc' with value 'A128CBC-HS256'
            var descriptor = new JweDescriptor(sharedEncryptionKey, KeyManagementAlgorithm.A256GcmKW, EncryptionAlgorithm.A256CbcHS512)
            {
                // Creates the JWS payload
                Payload = new JwsDescriptor(signatureKey, SignatureAlgorithm.HS256)
                {
                    Payload = new JwtPayload
                    {
                        // Defines the JWS claims
                        { JwtClaimNames.Iat, EpochTime.UtcNow },
                        { JwtClaimNames.Exp, EpochTime.UtcNow + EpochTime.OneHour },
                        { JwtClaimNames.Iss, "https://idp.example.com/" },
                        { JwtClaimNames.Aud, "636C69656E745F6964" }
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
