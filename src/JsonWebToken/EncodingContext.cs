using System;

namespace JsonWebToken
{
    public class EncodingContext
    {
        public EncodingContext(JsonHeaderCache headerCache, ISignerFactory signatureFactory, IKeyWrapperFactory keyWrapFactory, IAuthenticatedEncryptorFactory authenticatedEncryptionFactory)
        {
            HeaderCache = headerCache ?? throw new ArgumentNullException(nameof(headerCache));
            SignatureFactory = signatureFactory ?? throw new ArgumentNullException(nameof(signatureFactory));
            KeyWrapFactory = keyWrapFactory ?? throw new ArgumentNullException(nameof(keyWrapFactory));
            AuthenticatedEncryptionFactory = authenticatedEncryptionFactory ?? throw new ArgumentNullException(nameof(authenticatedEncryptionFactory));
        }

        public JsonHeaderCache HeaderCache { get; }

        public ISignerFactory SignatureFactory { get;  }

        public IKeyWrapperFactory KeyWrapFactory { get;  }

        public IAuthenticatedEncryptorFactory AuthenticatedEncryptionFactory { get; }
    }
}