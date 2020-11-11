namespace JsonWebToken.Tests
{
    public abstract class KeyWrapperTestsBase
    {
        public virtual Jwk WrapKey(KeyWrapper wrapper, Jwk keyToWrap, out JwtHeader header)
        {
            var destination = new byte[wrapper.GetKeyWrapSize()];
            header = new JwtHeader();
            var cek = wrapper.WrapKey(keyToWrap, header, destination);

            return cek;
        }
    }
}
