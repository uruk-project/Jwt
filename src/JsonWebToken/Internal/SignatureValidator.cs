// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    /// <summary>
    /// Reprensents the information required for a signature validation.
    /// </summary>
    public sealed class SignatureValidationContext
    {
        internal static readonly SignatureValidationContext NoSignatureContext = new SignatureValidationContext(new EmptyKeyProvider(), true, null);

        private readonly IKeyProvider _keyProvider;
        private readonly bool _supportUnsecure;
        private readonly SignatureAlgorithm? _algorithm;

        /// <summary>
        /// Initailzies a new instance of the <see cref="SignatureValidationContext"/> class.
        /// </summary>
        /// <param name="keyProvider"></param>
        /// <param name="supportUnsecure"></param>
        /// <param name="algorithm"></param>
        public SignatureValidationContext(IKeyProvider keyProvider, bool supportUnsecure, SignatureAlgorithm? algorithm)
        {
            _keyProvider = keyProvider;
            _supportUnsecure = supportUnsecure;
            _algorithm = algorithm;
        }

        /// <summary>
        /// Gets the <see cref="IKeyProvider"/>.
        /// </summary>
        public IKeyProvider KeyProvider => _keyProvider;

        /// <summary>
        /// Gets whether the unsecure tokens are supported.
        /// </summary>
        public bool SupportUnsecure => _supportUnsecure;

        /// <summary>
        /// Gets the <see cref="SignatureAlgorithm"/>.
        /// </summary>
        public SignatureAlgorithm? Algorithm => _algorithm;
    }
}
