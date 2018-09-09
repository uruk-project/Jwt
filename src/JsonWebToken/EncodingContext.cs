using System;

namespace JsonWebToken
{
    public class EncodingContext
    {
        public EncodingContext(JsonHeaderCache headerCache, SignerFactory signatureFactory, KeyWrapperFactory keyWrapFactory, AuthenticatedEncryptorFactory authenticatedEncryptionFactory)
        {
            HeaderCache = headerCache ?? throw new ArgumentNullException(nameof(headerCache));
            SignatureFactory = signatureFactory ?? throw new ArgumentNullException(nameof(signatureFactory));
            KeyWrapFactory = keyWrapFactory ?? throw new ArgumentNullException(nameof(keyWrapFactory));
            AuthenticatedEncryptionFactory = authenticatedEncryptionFactory ?? throw new ArgumentNullException(nameof(authenticatedEncryptionFactory));
        }

        public JsonHeaderCache HeaderCache { get; }

        public SignerFactory SignatureFactory { get;  }

        public KeyWrapperFactory KeyWrapFactory { get;  }

        public AuthenticatedEncryptorFactory AuthenticatedEncryptionFactory { get; }
    }
}