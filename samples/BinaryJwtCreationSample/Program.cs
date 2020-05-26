using JsonWebToken;
using System;

namespace BinaryJwtCreationSample
{
    class Program
    {
        static void Main()
        {
            // Creates a symmetric key for encryption
            var encryptionKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4T");

            // Creates a JWE descriptor with all its properties
            var payload = new byte[] { 76, 105, 102, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32, 112, 114, 111, 115, 112, 101, 114, 46 };
            var descriptor = new BinaryJweDescriptor(payload)
            {
                EncryptionKey = encryptionKey,
                EncryptionAlgorithm = EncryptionAlgorithm.Aes128CbcHmacSha256,
                Algorithm = KeyManagementAlgorithm.Aes128KW
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
