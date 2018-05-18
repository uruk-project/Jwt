using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;
using System;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class JwtWriter_UseSpan
    {
        private static readonly string RsaKey = "    {" +
"   \"kty\": \"RSA\"," +
"   \"d\": \"B-hunFHOixikOLMI0rUdw5tfD60FalN3bURc49gFcQq2JVxQFJJykPUADPBljpBqB4qqpufTmUJ2IhN5sLaWzeRw2Lx35DO8PlwfwTrsJRTefPVap03JfyMTif-9K8x9ickosRzS30w1xJocm34GfiAVIQUE1wP3wO2mD-Blv6PqcC5xq7s92hYURtkeqhqa1Dtnt4mSjJm-Fj2LaShtw9oYI1pSESKEmVmun0LQPosqKzHptXe3UPj7zzbAxkaE8CNrJwqFnl_H5p8PbaDSoYY1dnd91CTcbSqiuBfGbVutNv9cDdhe3kN_UO4hYqQEhu1EPP84ICILWtyFJbpywQ\"," +
"   \"e\": \"AQAB\"," +
"   \"use\": \"sig\"," +
"   \"kid\": \"rsa-256\"," +
"   \"n\": \"XGX8SrAH5DaOL-OW7DwVwhJJcDwc_3JpGVI03JQeK-nfamjy2aPbdceK4fFq46fZS2KMMH4VUXjIqX4YYYB1C5qenD5IashiUJ5hGCzKdp8Vq-wVNRm7fU994ZH3rBi1BkjdXvTol3xrkS2mhpQO-iN5gDZOaaZldH54eGv4JsjAskI8rS2lZ0mDzx03V1CQe-CnrFA1sFpaiOcAjGrCCaneRSB4NI4CyxfJDUGGs76-NftRWEJspXTzgP3fPhzTOQ5bm87Dxc_-si4ZF2VnC4w5bBG2c2iWAsegGwc-wWoF19_Tu_9SOYEeYJFHjixBQyCCbL4776PtwjI_uZTjow\"," +
"   \"p\": \"qR6OHmR9szCqr--IOWV5VdAZkLmLenIR_Ch_E5mUrO3sta4VdizPIkGtVTpuUpoYDeW2NreYgv3VVnYphc0UXrvbna80U0Na0vprNo0nDuypKX4eJ3Q2HYEoYCjbcKhrIpjwTBiT7MzLLL0XC5BZUGFy3WJRsHCejTfK_rQE2mE\"," +
"   \"q\": \"i92aBLeNmPhqO5Kor3pLes3QrTNtsLE9J77DOS65eBc6FAf7vqS5RoEwCIY4Or9azQ0JgFgHk-jgV50JkTalFcEMzQ5Yxxhes_AJzwUY89TpCrISlLf3P5dAxzz0PH86Ax47BICq2aSmWpfdQsG9--3ftIvunbDaaB8PwooTpIM\"," +
"   \"dp\": \"fIh-eIzhLwlAN0u4USOS5IjXuoWW2rSS387mPIWUQH73FpW5QgsfAAfC3oanZHYKDnm_4qzxRkwqQ3_BdcCdJmFJB-VTL5jikYdLWaE5SLkmm-I9zCm8C5_nHmAXru6l7ZUXJcHXc8EeP7SB-sbxrcoEblcO9lEHv8980G-5PyE\"," +
"   \"dq\": \"HEKobi-QYso-3M6jWuGBAs03TufHUB5f1voKhDFWtFctGwMJ8NljvkU4KWDFV8l2VVw_ATnIPjCds9Y9KqQ58w1QwtYVRhU8fWsQ8E19Xzcz5z9X1cjeInEzW46LYvXqCNtA3YYJ_3PvUPrCcEypUJAd1WM40Y_8cXFlQ8-WbHU\"," +
"   \"qi\": \"i4CUq5Lt1WXe-bzAap2t_es2n_aMZARHTcFOCg6mlmGlAYr02L7ALrMy9f8C9lljJ49v-KrhxjjQLk7M_O4uKQR3CO28zt0l9v0bgUb8o2Gdxry3YjVdcqUMRq5op3DHtWtB_EyElZqinnJPhZs9QlnzQ3-92U08vQcRnrhvmK4\"," +
"   \"alg\": \"RS256\"" +
" }";

        private static readonly JsonWebKey CustomSharedKey = JsonWebKey.FromJson(RsaKey) as RsaJwk;

        private static readonly JsonWebTokenDescriptor CustomSmallDescriptor = CreateCustomSmallDescriptor();
        public static readonly JsonWebTokenWriter Writer = new JsonWebTokenWriter();


        [Benchmark(Baseline = true)]
        public void DoNotUseSpan()
        {
            var value = Writer.WriteToken(CustomSmallDescriptor, useSpan: false);
        }

        [Benchmark]
        public void UseSpan()
        {
            var value = Writer.WriteToken(CustomSmallDescriptor, useSpan: true);
        }


        private static JsonWebTokenDescriptor CreateCustomSmallDescriptor()
        {
            var expires = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc);
            var issuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc);
            var issuer = "https://idp.example.com/";
            var audience = "636C69656E745F6964";
            //var jti = "756E69717565206964656E746966696572";
            var descriptor = new JsonWebTokenDescriptor()
            {
                IssuedAt = issuedAt,
                Expires = expires,
                Issuer = issuer,
                Audience = audience,
                SigningKey = CustomSharedKey
            };
            return descriptor;
        }
    }
}
