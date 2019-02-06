// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    public sealed class SignatureValidationContext
    {
        private readonly IKeyProvider _keyProvider;
        private readonly bool _supportUnsecure;
        private readonly SignatureAlgorithm _algorithm;

        public SignatureValidationContext(IKeyProvider keyProvider, bool supportUnsecure, SignatureAlgorithm algorithm)
        {
            _keyProvider = keyProvider;
            _supportUnsecure = supportUnsecure;
            _algorithm = algorithm;
        }

        public IKeyProvider KeyProvider => _keyProvider;

        public bool SupportUnsecure => _supportUnsecure;

        public SignatureAlgorithm Algorithm => _algorithm;
    }
}
