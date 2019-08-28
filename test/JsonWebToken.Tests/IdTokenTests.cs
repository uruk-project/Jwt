using System;
using System.Linq;
using System.Text;
using JsonWebToken.Internal;
using Xunit;

namespace JsonWebToken.Tests
{
    public class IdTokenTests
    {
        [Fact]
        public void Create()
        {
            var descriptor = new IdTokenDescriptor();
            descriptor.Algorithm = SignatureAlgorithm.None;
            descriptor.Issuer = "http://server.example.com";
            descriptor.Subject = "248289761001";
            descriptor.Audience = "s6BhdRkqt3";
            descriptor.Nonce = "n-0S6_WzA2Mj";
            descriptor.ExpirationTime = EpochTime.ToDateTime(1311281970);
            descriptor.IssuedAt = EpochTime.ToDateTime(1311280970);
            descriptor.AddClaim(Encoding.UTF8.GetBytes("name"), "Jane Doe");
            descriptor.GivenName = "Jane";
            descriptor.FamilyName = "Doe";
            descriptor.Gender = "female";
            descriptor.Birthdate = "0000-10-31";
            descriptor.Email = "janedoe@example.com";
            descriptor.Picture = "http://example.com/janedoe/me.jpg";

            var writer = new JwtWriter();
            var jwt = writer.WriteTokenString(descriptor);
            Assert.Equal("eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwic3ViIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoiczZCaGRSa3F0MyIsIm5vbmNlIjoibi0wUzZfV3pBMk1qIiwiZXhwIjoxMzExMjgxOTcwLCJpYXQiOjEzMTEyODA5NzAsIm5hbWUiOiJKYW5lIERvZSIsImdpdmVuX25hbWUiOiJKYW5lIiwiZmFtaWx5X25hbWUiOiJEb2UiLCJnZW5kZXIiOiJmZW1hbGUiLCJiaXJ0aGRhdGUiOiIwMDAwLTEwLTMxIiwiZW1haWwiOiJqYW5lZG9lQGV4YW1wbGUuY29tIiwicGljdHVyZSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9qYW5lZG9lL21lLmpwZyJ9.", jwt);
            //Assert.Equal("eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOlx1MDAyZlx1MDAyZnNlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMSIsImF1ZCI6InM2QmhkUmtxdDMiLCJub25jZSI6Im4tMFM2X1d6QTJNaiIsImV4cCI6MTMxMTI4MTk3MCwiaWF0IjoxMzExMjgwOTcwLCJuYW1lIjoiSmFuZSBEb2UiLCJnaXZlbl9uYW1lIjoiSmFuZSIsImZhbWlseV9uYW1lIjoiRG9lIiwiZ2VuZGVyIjoiZmVtYWxlIiwiYmlydGhkYXRlIjoiMDAwMC0xMC0zMSIsImVtYWlsIjoiamFuZWRvZUBleGFtcGxlLmNvbSIsInBpY3R1cmUiOiJodHRwOlx1MDAyZlx1MDAyZmV4YW1wbGUuY29tXHUwMDJmamFuZWRvZVx1MDAyZm1lLmpwZyJ9.", jwt);
        }

        [Fact]
        public void Read()
        {
            var key = new RsaJwk
            (
                n: "w7Zdfmece8iaB0kiTY8pCtiBtzbptJmP28nSWwtdjRu0f2GFpajvWE4VhfJAjEsOcwYzay7XGN0b-X84BfC8hmCTOj2b2eHT7NsZegFPKRUQzJ9wW8ipn_aDJWMGDuB1XyqT1E7DYqjUCEOD1b4FLpy_xPn6oV_TYOfQ9fZdbE5HGxJUzekuGcOKqOQ8M7wfYHhHHLxGpQVgL0apWuP2gDDOdTtpuld4D2LK1MZK99s9gaSjRHE8JDb1Z4IGhEcEyzkxswVdPndUWzfvWBBWXWxtSUvQGBRkuy1BHOa4sP6FKjWEeeF7gm7UMs2Nm2QUgNZw6xvEDGaLk4KASdIxRQ",
                e: "AQAB"
            )
            {
                Kid = "1e9gdk7",
                Alg = SignatureAlgorithm.RsaSha256.Utf8Name
            };
            var reader = new JwtReader();

            var policy = new TokenValidationPolicyBuilder()
                                .RequireSignature(key)
                                .Build();

            var result = reader.TryReadToken("eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAsCiAibmFtZSI6ICJKYW5lIERvZSIsCiAiZ2l2ZW5fbmFtZSI6ICJKYW5lIiwKICJmYW1pbHlfbmFtZSI6ICJEb2UiLAogImdlbmRlciI6ICJmZW1hbGUiLAogImJpcnRoZGF0ZSI6ICIwMDAwLTEwLTMxIiwKICJlbWFpbCI6ICJqYW5lZG9lQGV4YW1wbGUuY29tIiwKICJwaWN0dXJlIjogImh0dHA6Ly9leGFtcGxlLmNvbS9qYW5lZG9lL21lLmpwZyIKfQ.rHQjEmBqn9Jre0OLykYNnspA10Qql2rvx4FsD00jwlB0Sym4NzpgvPKsDjn_wMkHxcp6CilPcoKrWHcipR2iAjzLvDNAReF97zoJqq880ZD1bwY82JDauCXELVR9O6_B0w3K-E7yM2macAAgNCUwtik6SjoSUZRcf-O5lygIyLENx882p6MtmwaL1hd6qn5RZOQ0TLrOYu0532g9Exxcm-ChymrB4xLykpDj3lUivJt63eEGGN6DH5K6o33TcxkIjNrCD4XB1CKKumZvCedgHHF3IAK4dVEDSUoGlH9z4pP_eWYNXvqQOjGs-rDaQzUHl6cQQWNiDpWOl_lxXjQEvQ".AsSpan(), policy);
            var token = result.Token.AsIdToken();

            Assert.Equal("http://server.example.com", token.Issuer);
            Assert.Equal("248289761001", token.Subject);
            Assert.Equal("s6BhdRkqt3", token.Audiences.FirstOrDefault());
            Assert.Equal("n-0S6_WzA2Mj", token.Nonce);
            Assert.Equal(EpochTime.ToDateTime(1311281970), token.ExpirationTime);
            Assert.Equal(EpochTime.ToDateTime(1311280970), token.IssuedAt);
            Assert.Equal("Jane Doe", token.Payload["name"]);
            Assert.Equal("Jane", token.GivenName);
            Assert.Equal("Doe", token.FamilyName);
            Assert.Equal("female", token.Gender);
            Assert.Equal("0000-10-31", token.Birthdate);
            Assert.Equal("janedoe@example.com", token.Email);
            Assert.Equal("http://example.com/janedoe/me.jpg", token.Picture);
        }
    }
}
