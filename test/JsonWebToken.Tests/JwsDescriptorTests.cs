using JsonWebToken.Internal;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JwsDescriptorTests
    {
        [Fact]
        public void Encode()
        {
            var descriptor = new JwsDescriptor();
            var context = new EncodingContext(new DefaultSignerFactory(), new DefaultKeyWrapperFactory(), new DefaultAuthenticatedEncryptorFactory(), new JsonHeaderCache(), 1, true);
            using (var bufferWriter = new ArrayBufferWriter<byte>())
            {
                descriptor.Encode(context, bufferWriter);

                var reader = new JwtReader();
                var result = reader.TryReadToken(bufferWriter.WrittenSpan, TokenValidationPolicy.NoValidation);
                Assert.True(result.Succedeed);
                Assert.NotNull(result.Token);
                Assert.True(result.Token.ExpirationTime.HasValue);
                Assert.True(result.Token.IssuedAt.HasValue);
            }
        }
    }
}
