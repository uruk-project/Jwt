using System;
using Xunit;

namespace JsonWebToken.Tests
{
    public class TrustVectorTests
    {
        [Theory]
        [InlineData("P0")]
        [InlineData("P1")]
        [InlineData("Ca")]
        [InlineData("Cb")]
        [InlineData("Ma")]
        [InlineData("Mb")]
        [InlineData("Aa")]
        [InlineData("P1.Cc.Cd.Aa")]
        [InlineData("Aa.Cc.Cd.P1")]
        [InlineData("Aa.P1.Cd.Cc")]
        [InlineData("Cd.P1.Cc.Aa")]
        [InlineData("P1.Cc.Ab")]
        [InlineData("P1.Cc.Ac")]
        [InlineData("P1.Cb.Cc.Ab")]
        [InlineData("Ce.Ab")]
        public void Ctor(string vector)
        {
            var trustVector = new TrustVector(vector);
        }

        [Theory]
        [InlineData("P")]
        [InlineData("P0.P")]
        [InlineData("P0P0")]
        [InlineData("p0")]
        [InlineData("P#")]
        [InlineData("0a")]
        [InlineData("Cb.Cb")]
        [InlineData("Cb-Cb")]
        [InlineData("CbxCb")]
        [InlineData("Ma.")]
        [InlineData("Ma..")]
        [InlineData("Ma...")]
        public void Ctor_ArgumentException(string vector)
        {
            Assert.Throws<ArgumentException>(() => new TrustVector(vector));
        }

        [Fact]
        public void Ctor_ArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => new TrustVector(string.Empty));
            Assert.Throws<ArgumentNullException>(() => new TrustVector(null));
        }
    }
}
