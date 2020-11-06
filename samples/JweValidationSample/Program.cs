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
            var encryptionKey = SymmetricJwk.FromBase64Url("R9MyWaEoyiMYViVWo8Fk4T");

            var policy = new TokenValidationPolicyBuilder()
                           .RequireIssuer("https://idp.example.com/", signatureKey, SignatureAlgorithm.HmacSha256)
                           .RequireAudience("636C69656E745F6964")
                           .WithDecryptionKey(encryptionKey)
                           .Build();

            var result = Jwt.TryParse("eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiQTEyOEtXIn0.f3VIyjZSlzfxTakllbEQeCIU9xSkoqf9duUsbyqTOs8K9EKu_6xcFw.qbmqiA67XDA89YcmsHWwaA.SiqMox7oLg-kIDN0iGifdtX5ILsL5IyziJJp07O-GTx5OFWSsWiB-5Q_GI8CeGBIaEswpfhR9ND9a6YcqKFFT0pTPnw4cI3tcFOcKgjq1ofCZeu4BQkoifH9QuD744MsNVxGekx-rUQQ8OMcnO7q9sHmc4xkQwRDh8GTjd353mRElJMWU_OBswMc4JnMHYHa9cj4u2f9rqKDG1VHIAFai8A1rhfk8Eh7D7MHWQ1CyrN1enYW7veg2adEbr9VH4qG3hCzsOzUyBWx6aJcrwuGHw.T07kRuo-d66j3lPxFzXfQSFeokkInOzofAx3LWh9v-w", policy, out var jwt);
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
