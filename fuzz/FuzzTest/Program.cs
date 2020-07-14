using JsonWebToken;
using SharpFuzz;

namespace FuzzTest
{
    class Program
    {
        private static readonly Jwk SigningKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");
        private static readonly Jwk EncryptionKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4T");
        private static readonly JwtReader reader = new JwtReader(EncryptionKey);
        private static readonly TokenValidationPolicy Policy = new TokenValidationPolicyBuilder().RequireSignature(SigningKey, SignatureAlgorithm.HmacSha256).Build();

        static void Main()
        {
            //var result = reader.TryReadToken( "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiQTEyOEtXIn0.YiNMTSrtoRmWYx_xJHEiMR4mo52yKpbtcUcxbAYTdCJ8bQdk9RALzA.lvV2ZT_uHEdo8eBu4ATsYg.ZOC6xD9xrsWC07cwTXvtfqsulSDhPm1l3cQC4JdAvCbZt7AO7y5u6vcoJYhTvjxL1fMK1L7J6w_Pf8QnHtPAvDMcUvVlv4tTI4XekBOAVwGaEFKvtjPtjwVgwhinwmUmz_vXR9t_Po8lXqb-J43ndsquIJlqcTsR4XJhz5C2Sm7O_9rkc35sK84QUm0eUxz3E1J_8Hofbw8l-7htT_c9NV2PpLledKrutzAVFxMfjgTV8NkcBdBBlCYvI7sO1R56O-XqMOrvXQS3NU9fx3Pw9A.Vna_xJYv05w_UysnrOpkSvQDyiUiyy8FVoWXbVElwjE", Policy);
            //System.Console.WriteLine(result.Status);
            Fuzzer.Run(Jwt_Read);
        }

        private static void Jwt_Read(string value)
        {
            reader.TryReadToken(value, Policy);
        }
    }
}
