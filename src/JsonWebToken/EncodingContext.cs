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
        public EncodingContext(ISignerFactory signatureFactory, IKeyWrapperFactory keyWrapFactory, IAuthenticatedEncryptorFactory authenticatedEncryptionFactory, JsonHeaderCache headerCache)
        {
            SignatureFactory = signatureFactory ?? throw new ArgumentNullException(nameof(signatureFactory));
            KeyWrapFactory = keyWrapFactory ?? throw new ArgumentNullException(nameof(keyWrapFactory));
            AuthenticatedEncryptionFactory = authenticatedEncryptionFactory ?? throw new ArgumentNullException(nameof(authenticatedEncryptionFactory));
            HeaderCache = headerCache;
        }

        public JsonHeaderCache HeaderCache { get; }

        public ISignerFactory SignatureFactory { get;  }

        public IKeyWrapperFactory KeyWrapFactory { get;  }

        public IAuthenticatedEncryptorFactory AuthenticatedEncryptionFactory { get; }
    }
}