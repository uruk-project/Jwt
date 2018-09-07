using System;

namespace JsonWebToken
{
    public class EncodingContext
    {
        public EncodingContext(JsonHeaderCache headerCache, SignatureFactory signatureFactory, KeyWrapFactory keyWrapFactory, AuthenticatedEncryptionFactory authenticatedEncryptionFactory)
        {
            HeaderCache = headerCache ?? throw new ArgumentNullException(nameof(headerCache));
            SignatureFactory = signatureFactory ?? throw new ArgumentNullException(nameof(signatureFactory));
            KeyWrapFactory = keyWrapFactory ?? throw new ArgumentNullException(nameof(keyWrapFactory));
            AuthenticatedEncryptionFactory = authenticatedEncryptionFactory ?? throw new ArgumentNullException(nameof(authenticatedEncryptionFactory));
        }

        public JsonHeaderCache HeaderCache { get; }

        public SignatureFactory SignatureFactory { get;  }

        public KeyWrapFactory KeyWrapFactory { get;  }

        public AuthenticatedEncryptionFactory AuthenticatedEncryptionFactory { get; }
    }
}