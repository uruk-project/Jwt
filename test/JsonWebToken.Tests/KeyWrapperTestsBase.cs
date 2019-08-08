using Xunit;

namespace JsonWebToken.Tests
{
    public abstract class KeyWrapperTestsBase
    {
        public virtual Jwk WrapKey(KeyWrapper wrapper, Jwk keyToWrap, out JwtObject header)
        {
            var destination = new byte[wrapper.GetKeyWrapSize()];
            header = new JwtObject();
            wrapper.WrapKey(keyToWrap, header, destination, out var cek, out int bytesWritten);

            Assert.Equal(destination.Length, bytesWritten);

            return cek;
        }
    }
}
