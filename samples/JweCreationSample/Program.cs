using System;
using JsonWebToken;

namespace JweCreationSample
{
    class Program
    {
        static void Main()
        {
            // Creates the RSA key defined for the 'PS512' signature algorithm
            var privateKey = ECJwk.GeneratePrivateKey(SignatureAlgorithm.EcdsaSha512);

            // Creates the JWS descriptor 
            // The descriptor sets the 'alg' with value 'PS512'
            var descriptor = new JwsDescriptor(privateKey, SignatureAlgorithm.EcdsaSha512)
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
