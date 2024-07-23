using Xunit;

namespace JsonWebToken.Tests
{
    public class ClientAssertionDescriptorTests
    {
        [Fact]
        public void Create()
        {   
            var descriptor = new ClientAssertionDescriptor(SymmetricJwk.GenerateKey(256), SignatureAlgorithm.HS256)
            {
                Payload = new JwtPayload
                {
                    { "iss", "http://server.example.com"},
                    { "sub", "248289761001" },
                    { "aud", "s6BhdRkqt3" },
                    { "exp", 1311281970 },
                    { "iat", 1311280970 }
                }
            };
            var writer = new JwtWriter();
            var jwt = writer.WriteTokenString(descriptor);
          //  Assert.Equal("eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwic3ViIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoiczZCaGRSa3F0MyIsIm5vbmNlIjoibi0wUzZfV3pBMk1qIiwiZXhwIjoxMzExMjgxOTcwLCJpYXQiOjEzMTEyODA5NzAsIm5hbWUiOiJKYW5lIERvZSIsImdpdmVuX25hbWUiOiJKYW5lIiwiZmFtaWx5X25hbWUiOiJEb2UiLCJnZW5kZXIiOiJmZW1hbGUiLCJiaXJ0aGRhdGUiOiIwMDAwLTEwLTMxIiwiZW1haWwiOiJqYW5lZG9lQGV4YW1wbGUuY29tIiwicGljdHVyZSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9qYW5lZG9lL21lLmpwZyJ9.", jwt);
            //Assert.Equal("eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOlx1MDAyZlx1MDAyZnNlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMSIsImF1ZCI6InM2QmhkUmtxdDMiLCJub25jZSI6Im4tMFM2X1d6QTJNaiIsImV4cCI6MTMxMTI4MTk3MCwiaWF0IjoxMzExMjgwOTcwLCJuYW1lIjoiSmFuZSBEb2UiLCJnaXZlbl9uYW1lIjoiSmFuZSIsImZhbWlseV9uYW1lIjoiRG9lIiwiZ2VuZGVyIjoiZmVtYWxlIiwiYmlydGhkYXRlIjoiMDAwMC0xMC0zMSIsImVtYWlsIjoiamFuZWRvZUBleGFtcGxlLmNvbSIsInBpY3R1cmUiOiJodHRwOlx1MDAyZlx1MDAyZmV4YW1wbGUuY29tXHUwMDJmamFuZWRvZVx1MDAyZm1lLmpwZyJ9.", jwt);
        }
    }
}
