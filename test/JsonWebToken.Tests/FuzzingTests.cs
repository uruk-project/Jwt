using Xunit;

namespace JsonWebToken.Tests
{
    public class FuzzingTests
    {
        static Jwk key = SymmetricJwk.GenerateKey(256);
        static JwtReader reader = new JwtReader(key);

        [Theory]
        [InlineData("åyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwIiwibmFtZSI6IkplIiwiaWF0IjoyfQ.")]
        [InlineData("eyJhbGciOiJIUzI1NbIsInR5cCI6CI6IkpXVCJ9.eyJzdWIiOiIwIiwib‚‚‚‚‚‚‚‚‚‚IiOmFiwiaW>0IIsInR5cCI6CI6IkpjoyfQ.")]
        [InlineData("eyJhbGciOiJiUzI1NiIsInR5cCI6IopXVCJ9.eyJzdWIiOiIwIiwibmFtZSI6IkplIiwiaWF0IjoyfQ.")]
        public void Fuzz(string value)
        {
            var result = reader.TryReadToken(value, TokenValidationPolicy.NoValidation);

            Assert.NotNull(result);
        }
    }
}
