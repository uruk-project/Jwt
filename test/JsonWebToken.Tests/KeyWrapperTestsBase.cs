using Xunit;

namespace JsonWebToken.Tests
{
    public abstract class KeyWrapperTestsBase
    {
        public virtual Jwk WrapKey(KeyWrapper wrapper, Jwk keyToWrap, out JwtObject header)
        {
            var destination = new byte[wrapper.GetKeyWrapSize()];
            header = new JwtObject();
            var cek = wrapper.WrapKey(keyToWrap, header, destination);

            return cek;
        }
    }
}
