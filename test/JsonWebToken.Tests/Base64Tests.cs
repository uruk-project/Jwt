using System;
using System.Text;
using Xunit;

namespace JsonWebToken.Tests
{
    public class Base64Tests
    {
        [Theory]
        [InlineData("", "")]
        [InlineData("SGVsbG8=", "Hello")]
        [InlineData("SGVsbG8gV29ybGQ=", "Hello World")]
        [InlineData("SGVsbG8\tgV29ybGQ=", "Hello World")]
        [InlineData("SGVsbG8\rgV29ybGQ=", "Hello World")]
        [InlineData("SGVsbG8\ngV29ybGQ=", "Hello World")]
        [InlineData("SGVsbG8\vgV29ybGQ=", "Hello World")]
        [InlineData("SGVsbG8\fgV29ybGQ=", "Hello World")]
        [InlineData("SGVsbG8 gV29ybGQ=", "Hello World")]
        [InlineData(" SGVsbG8gV29ybGQ=", "Hello World")]
        [InlineData("SG Vsb G8gV29ybGQ=", "Hello World")]
        [InlineData("S G V s b G 8 g V 2 9 y b G Q =", "Hello World")]
        [InlineData("S  G    V     s       b         G8gV29ybGQ=", "Hello World")]
        [InlineData(" S  G    V     s       b         G8gV29ybGQ= ", "Hello World")]
        [InlineData("SGV+bG8=", "He~lo")]
        [InlineData("SGV/bG8=", "He\u007flo")]
        public void Decode_Valid(string value, string expected)
        {
            var result = Base64.Decode(Encoding.UTF8.GetBytes(value));
            Assert.NotNull(result);
            Assert.Equal(Encoding.UTF8.GetBytes(expected), result);
        }

        [Theory]
        [InlineData("SGVsbG8")]
        [InlineData("SGVsbG8&")]
        [InlineData("SGVsbG=8")]
        [InlineData("S-/sbG8=")]
        [InlineData("S+_sbG8=")]
        public void Decode_Invalid(string value)
        {
            Assert.Throws<FormatException>(() => Base64.Decode(Encoding.UTF8.GetBytes(value)));
        }
    }
}
