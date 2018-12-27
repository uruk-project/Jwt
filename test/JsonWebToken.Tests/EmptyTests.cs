using System;
using Xunit;

namespace JsonWebToken.Tests
{
    public class EmptyTests
    {
        [Fact]
        public void OK()
        {
            Assert.True(true);
        }

        [Fact]
        public void Stackalloc()
        {
            Span<byte> data = stackalloc byte[1024 * 1024 / 64];
            Assert.True(true);
        }
    }
}
