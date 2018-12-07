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
        /// <summary>
        /// Initializes a new instance of the <see cref="EncodingContext"/> class.
        /// </summary>
        /// <param name="signatureFactory"></param>
        /// <param name="keyWrapFactory"></param>
        /// <param name="authenticatedEncryptionFactory"></param>
        /// <param name="headerCache"></param>
        public EncodingContext(SignerFactory signatureFactory, KeyWrapperFactory keyWrapFactory, AuthenticatedEncryptorFactory authenticatedEncryptionFactory, JsonHeaderCache headerCache)
        {
            SignatureFactory = signatureFactory ?? throw new ArgumentNullException(nameof(signatureFactory));
            KeyWrapFactory = keyWrapFactory ?? throw new ArgumentNullException(nameof(keyWrapFactory));
            AuthenticatedEncryptionFactory = authenticatedEncryptionFactory ?? throw new ArgumentNullException(nameof(authenticatedEncryptionFactory));
            HeaderCache = headerCache;
        }
        
        /// <summary>
        /// The JSON header cache.
        /// </summary>
        public JsonHeaderCache HeaderCache { get; }

        /// <summary>
        /// The <see cref="SignatureFactory"/>.
        /// </summary>
        public SignerFactory SignatureFactory { get;  }

        /// <summary>
        /// The <see cref="KeyWrapperFactory"/>.
        /// </summary>
        public KeyWrapperFactory KeyWrapFactory { get;  }

        /// <summary>
        /// The <see cref="AuthenticatedEncryptorFactory"/>.
        /// </summary>
        public AuthenticatedEncryptorFactory AuthenticatedEncryptionFactory { get; }
    }
}