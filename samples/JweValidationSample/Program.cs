using System;
using JsonWebToken;

namespace JweValidationSample
{
    class Program
    {
        static void Main()
        {
            // Creates a symmetric key defined for the 'HS256' algorithm
            var signatureKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");

            // Creates a symmetric key for encryption
            var decryptionKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4T");

            var policy = new TokenValidationPolicyBuilder()
                           .RequireSignature("https://idp.example.com/", signatureKey, SignatureAlgorithm.HS256)
                           .RequireAudience("636C69656E745F6964")
                           .WithDecryptionKey(decryptionKey)
                           .Build();

            var result = Jwt.TryParse("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiZWFOTlpaMXBtREFXSWYzYkg3MFg2V3FfbldzUXhuMjFMUngza1daMG5MYyIsImN0eSI6IkpXVCJ9.PU18XXVByiJLE53zkg1m-SzjZXUdRYkl0X20JtsMKXW54RHn3fcK_w.Bu1SPUTuntwvPfwXTj1OhQ.OuCl09TjUMJk80GdY4n5r6HUnH21dWwT1BAbbvPJg75p_AfMvVNmaQ3dahrSmCkuCI5EF34ynE_qUBAuMH9bcplUWS9GDKJfGugEZgkciWORv5RzXvAAokpElpuaiV09SdBmaepi4FAXvTP4axJUWuOXt2MvjnlwbIXlVqUX9Lha1NnsseBLTjfCclhV0pQEKjnncqjuqTcxmqTqAsxZA1v8RJV_FbzBdVBWwQ-qrjYbsrqtsK13XazZEGwAHU7fJT1vlaBdlni6aTQIlwE7JuLA--6hRM9mr7NZ4SlihCFBLjW-DZ2QoQBd6XeFNGKMnNgUP0t6mYihPlmh1eC0BivPaTtCKf4CH6lrq42_17s.ajGQE7r5eAd9z8a-8mmq2g", policy, out var jwt);
            if (result)
            {
                Console.WriteLine("The token is " + jwt);
            }
            else
            {
                Console.WriteLine("Failed to read the token. Reason: " + Environment.NewLine + jwt.Error.Status);
            }

            jwt.Dispose();
        }
    }
}
