using System;
using JsonWebToken;

namespace PlaintextJwtCreationSample
{
    class Program
    {
        static void Main()
        {
            // Creates a symmetric key for encryption
            var encryptionKey = new SymmetricJwk("R9MyWaEoyiMYViVWo8Fk4T");

            // Creates a JWE descriptor with all its properties
            var descriptor = new PlaintextJweDescriptor()
            {
                EncryptionKey = encryptionKey,
                EncryptionAlgorithm = EncryptionAlgorithm.Aes128CbcHmacSha256,
                Algorithm = KeyManagementAlgorithm.Aes128KW,
                Payload = "Life long and prosper.hello.world"
            };

            // Generates the UTF-8 string representation of the JWT
            var writer = new JwtWriter();
            var token = writer.WriteTokenString(descriptor);

            Console.WriteLine("The JWT is:");
            Console.WriteLine(descriptor);
            Console.WriteLine();
            Console.WriteLine("Its compact form is:");
            Console.WriteLine(token);

            var reader = new JwtReader(encryptionKey);
            var test = reader.TryReadToken(token, TokenValidationPolicy.NoValidation);
        }
    }
}
