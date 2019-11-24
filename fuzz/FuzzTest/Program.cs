using System;
using JsonWebToken;
using SharpFuzz;

namespace FuzzTest
{
    class Program
    {
        private static readonly Jwk Key = SymmetricJwk.FromBase64Url("Ozcp395qrEfQvD9Mz2EPkHcWz8jzFnINmyeMQjX3vBM");
        private static readonly JwtReader reader = new JwtReader();
        private static readonly TokenValidationPolicy Policy = new TokenValidationPolicyBuilder().RequireSignature(Key).Build();
        static void Main()
        {
            Fuzzer.Run(Jwt_Read);
        }

        private static void Jwt_Read(string value)
        {
            reader.TryReadToken(value, Policy);
        }
    }
}
