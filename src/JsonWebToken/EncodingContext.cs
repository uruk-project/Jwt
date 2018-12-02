// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Encapsulate the context required for a JWT encoding.
    /// </summary>
    public sealed class EncodingContext
    {
        public EncodingContext(SignerFactory signatureFactory, KeyWrapperFactory keyWrapFactory, AuthenticatedEncryptorFactory authenticatedEncryptionFactory, JsonHeaderCache headerCache)
        {
            SignatureFactory = signatureFactory ?? throw new ArgumentNullException(nameof(signatureFactory));
            KeyWrapFactory = keyWrapFactory ?? throw new ArgumentNullException(nameof(keyWrapFactory));
            AuthenticatedEncryptionFactory = authenticatedEncryptionFactory ?? throw new ArgumentNullException(nameof(authenticatedEncryptionFactory));
            HeaderCache = headerCache;
        }

        public JsonHeaderCache HeaderCache { get; }

        public SignerFactory SignatureFactory { get;  }

        public KeyWrapperFactory KeyWrapFactory { get;  }

        public AuthenticatedEncryptorFactory AuthenticatedEncryptionFactory { get; }
    }
}