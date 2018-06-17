using System.Collections.Generic;

namespace JsonWebToken
{
    public class BinaryJweDescriptor : EncodedJwtDescriptor<byte[]>
    {
        public BinaryJweDescriptor(byte[] payload)
            : base(new Dictionary<string, object>(), payload)
        {
        }

        public BinaryJweDescriptor(IDictionary<string, object> header, byte[] payload)
            : base(header, payload)
        {
        }

        public override string Encode()
        {
            return EncryptToken(Payload);
        }
    }
}
