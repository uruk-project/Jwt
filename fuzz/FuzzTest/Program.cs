using JsonWebToken;
using SharpFuzz;

namespace FuzzTest
{
    class Program
    {
        private static readonly Jwk SigningKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");
        private static readonly Jwk EncryptionKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4T");
        private static readonly TokenValidationPolicy Policy = new TokenValidationPolicyBuilder()
                                                                    .RequireSignature(SigningKey, SignatureAlgorithm.HmacSha256)
                                                                    .WithDecryptionKey(EncryptionKey)
                                                                    .Build();

        static void Main()
        {
            Fuzzer.Run(Jwt_Read);
        }

        private static void Jwt_Read(string value)
        {
            Jwt.TryParse(value, Policy, out _);
        }
    }
}
