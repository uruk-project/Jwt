using Xunit;

namespace JsonWebToken.Tests
{
    public class JwsDescriptorTests
    {
        [Fact]
        public void Encode()
        {
            var descriptor = new JwsDescriptor();
            using (var bufferWriter = new PooledByteBufferWriter())
            {
                var context = new EncodingContext(bufferWriter, new JsonHeaderCache(), 60, true);
                descriptor.Encode(context);

                var reader = new JwtReader();
                var result = reader.TryReadToken(bufferWriter.WrittenSpan, TokenValidationPolicy.NoValidation);
                Assert.True(result.Succedeed);
                Assert.NotNull(result.Token);
                Assert.True(result.Token.Payload.ContainsClaim("exp"));
                Assert.True(result.Token.Payload.ContainsClaim("iat"));
            }
        }
    }
}
