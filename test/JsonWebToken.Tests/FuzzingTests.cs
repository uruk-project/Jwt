using Xunit;

namespace JsonWebToken.Tests
{
    public class FuzzingTests
    {
        static Jwk key = SymmetricJwk.GenerateKey(256);

        [Theory]
        [InlineData("åyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwIiwibmFtZSI6IkplIiwiaWF0IjoyfQ.")]
        [InlineData("eyJhbGciOiJIUzI1NbIsInR5cCI6CI6IkpXVCJ9.eyJzdWIiOiIwIiwib‚‚‚‚‚‚‚‚‚‚IiOmFiwiaW>0IIsInR5cCI6CI6IkpjoyfQ.")]
        [InlineData("eyJhbGciOiJiUzI1NiIsInR5cCI6IopXVCJ9.eyJzdWIiOiIwIiwibmFtZSI6IkplIiwiaWF0IjoyfQ.")]
        public void Fuzz(string value)
        {
            var policy = new TokenValidationPolicyBuilder()
                            .IgnoreSignature()
                            .WithDecryptionKey(key)
                            .Build();
            var parsed = Jwt.TryParse(value, policy, out var jwt);

            Assert.NotNull(jwt);
            jwt.Dispose();
        }
    }
}
