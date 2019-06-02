using Xunit;

namespace JsonWebToken.Tests
{
    public abstract class KeyWrapperTestsBase
    {
        public virtual Jwk TryWrapKey(KeyWrapper wrapper, Jwk keyToWrap, out JwtObject header)
        {
            var destination = new byte[wrapper.GetKeyWrapSize()];
            header = new JwtObject();
            bool wrapped = wrapper.TryWrapKey(keyToWrap, header, destination, out var cek, out int bytesWritten);

            Assert.True(wrapped);
            Assert.Equal(destination.Length, bytesWritten);

            return cek;
        }
    }
}
