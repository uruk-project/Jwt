using System;
using System.Text;
using Xunit;

namespace JsonWebToken.Tests
{
    public class Base64UrlTests
    {
        [Theory]
        [InlineData("", "")]
        [InlineData("SGVsbG8", "Hello")]
        [InlineData("SGVsbG8gV29ybGQ", "Hello World")]
        [InlineData("SGV-bG8", "He~lo")]
        [InlineData("SGV_bG8", "He\u007flo")]
        public void Decode_Valid(string value, string expected)
        {
            var result = Base64Url.Decode(Encoding.UTF8.GetBytes(value));
            Assert.NotNull(result);
            Assert.Equal(Encoding.UTF8.GetBytes(expected), result);
        }

        [Theory]
        [InlineData("SGVsbG8=")]
        [InlineData("SGVsbG8 ")]
        [InlineData(" SGVsbG8")]
        [InlineData("SGV sbG8")]
        public void Decode_Invalid(string value)
        {
            Assert.Throws<FormatException>(() => Base64Url.Decode(Encoding.UTF8.GetBytes(value)));
        }

        [Fact]
        public void Decode_Null()
        {
            Assert.Throws<ArgumentNullException>(() => Base64Url.Decode((string)null));
        }
    }
}
