namespace JsonWebTokens
{
    public class PlaintextJweDescriptor : EncodedJwtDescriptor<string>
    {
        public override string Encode()
        {
            var payload = Payload;
            var rawData = EncryptToken(payload);

            return rawData;
        }
    }
}
