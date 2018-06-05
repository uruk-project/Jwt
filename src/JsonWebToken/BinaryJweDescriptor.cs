namespace JsonWebToken
{
    public class BinaryJweDescriptor : EncodedJwtDescriptor<byte[]>
    {
        public override string Encode()
        {
            return EncryptToken(Payload);
        }
    }
}
