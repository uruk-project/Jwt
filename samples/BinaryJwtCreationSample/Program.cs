using System;
using JsonWebToken;

namespace BinaryJwtCreationSample
{
    class Program
    {
        static void Main()
        {
            // Creates a symmetric key for encryption
            var encryptionKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4T");

            // Creates a JWE descriptor with all its properties
            var payload = "Life long and prosper."u8.ToArray();
            var descriptor = new BinaryJweDescriptor(encryptionKey, KeyManagementAlgorithm.A128KW, EncryptionAlgorithm.A128CbcHS256)
            {
                Payload = payload
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
