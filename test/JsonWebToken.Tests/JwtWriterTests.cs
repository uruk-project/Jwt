using JsonWebToken.Internal;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JwtWriterTests
    {
        [Fact]
        public void Write_Success()
        {
            const string expectedToken = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwic3ViIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoiczZCaGRSa3F0MyIsImV4cCI6MTMxMTI4MTk3MCwiaWF0IjoxMzExMjgwOTcwfQ.";
            var descriptor = new JwsDescriptor
            {
                Algorithm = SignatureAlgorithm.None,
                Issuer = "http://server.example.com",
                Subject = "248289761001",
                Audience = "s6BhdRkqt3",
                ExpirationTime = EpochTime.ToDateTime(1311281970),
                IssuedAt = EpochTime.ToDateTime(1311280970)
            };

            var writer = new JwtWriter();
            var jwt = writer.WriteTokenString(descriptor);
            Assert.Equal(expectedToken, jwt);
        }

        [Fact]
        public void Write_WithCachedHeader_Success()
        {
            const string expectedToken = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwic3ViIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoiczZCaGRSa3F0MyIsImV4cCI6MTMxMTI4MTk3MCwiaWF0IjoxMzExMjgwOTcwfQ.";
            var descriptor = new JwsDescriptor
            {
                Algorithm = SignatureAlgorithm.None,
                Issuer = "http://server.example.com",
                Subject = "248289761001",
                Audience = "s6BhdRkqt3",
                ExpirationTime = EpochTime.ToDateTime(1311281970),
                IssuedAt = EpochTime.ToDateTime(1311280970)
            };

            var writer = new JwtWriter();
            var jwt = writer.WriteTokenString(descriptor);
            var jwt2 = writer.WriteTokenString(descriptor);
            Assert.Equal(expectedToken, jwt);
            Assert.Equal(expectedToken, jwt2);
        }
    }
    public class JwtWriterXTests
    {
        [Fact]
        public void Write_Success()
        {
            const string expectedToken = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwic3ViIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoiczZCaGRSa3F0MyIsImV4cCI6MTMxMTI4MTk3MCwiaWF0IjoxMzExMjgwOTcwfQ.";
            var descriptor = new JwsDescriptorX
            {
                Alg = SignatureAlgorithm.None,
                Payload = new JwtPayloadX
                {
                    { "iss", "http://server.example.com" },
                    { "sub", "248289761001" },
                    { "aud" , "s6BhdRkqt3" },
                    { "exp", 1311281970 },
                    { "iat", 1311280970 }
                }
            };

            var writer = new JwtWriterX();
            var jwt = writer.WriteTokenString(descriptor);
            Assert.Equal(expectedToken, jwt);
        }

        [Fact]
        public void Write_WithCachedHeader_Success()
        {
            const string expectedToken = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwic3ViIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoiczZCaGRSa3F0MyIsImV4cCI6MTMxMTI4MTk3MCwiaWF0IjoxMzExMjgwOTcwfQ.";
            var descriptor = new JwsDescriptorX
            {
                Alg = SignatureAlgorithm.None,
                Payload = new JwtPayloadX
                {
                    { "iss", "http://server.example.com" },
                    { "sub", "248289761001" },
                    { "aud" , "s6BhdRkqt3" },
                    { "exp", 1311281970 },
                    { "iat", 1311280970 }
                }
            };


            var writer = new JwtWriterX();
            var jwt = writer.WriteTokenString(descriptor);
            var jwt2 = writer.WriteTokenString(descriptor);
            Assert.Equal(expectedToken, jwt);
            Assert.Equal(expectedToken, jwt2);
        }
    }
}