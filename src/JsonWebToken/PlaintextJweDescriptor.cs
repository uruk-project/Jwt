namespace JsonWebToken
{
    public class PlaintextJweDescriptor : JweDescriptor<string>
    {
        public override string Encode()
        {
            var payload = Payload;
            var rawData = EncryptToken(payload);

            return rawData;
        }
    }
}
