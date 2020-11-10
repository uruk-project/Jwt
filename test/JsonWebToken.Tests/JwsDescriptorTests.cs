using Xunit;

namespace JsonWebToken.Tests
{
    public class JwsDescriptorTests
    {
        [Fact]
        public void EncodeEmpty()
        {
            var descriptor = new JwsDescriptor(Jwk.None, SignatureAlgorithm.None);
            using (var bufferWriter = new PooledByteBufferWriter())
            {
                var context = new EncodingContext(bufferWriter, new LruJwtHeaderCache(), 60, true);
                descriptor.Encode(context);

                var result = Jwt.TryParse(bufferWriter.WrittenSpan, TokenValidationPolicy.NoValidation, out var jwt);
                Assert.True(result);
                Assert.NotNull(jwt);
                Assert.True(jwt.Payload.ContainsClaim("exp"));
                Assert.True(jwt.Payload.ContainsClaim("iat"));
                jwt.Dispose();
            }
        }
    }
}
