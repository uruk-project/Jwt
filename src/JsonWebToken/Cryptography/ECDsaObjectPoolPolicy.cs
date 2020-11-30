// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_ELLIPTIC_CURVE_SIGNATURE
using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    internal sealed class ECDsaObjectPoolPolicy : PooledObjectFactory<ECDsa>
    {
        private readonly ECJwk _key;
        private readonly SignatureAlgorithm _algorithm;
        private readonly bool _usePrivateKey;

        public ECDsaObjectPoolPolicy(ECJwk key, SignatureAlgorithm algorithm)
        {
            _key = key;
            _algorithm = algorithm;
            _usePrivateKey = key.HasPrivateKey;
        }

        public override ECDsa Create()
            => _key.CreateECDsa(_algorithm, _usePrivateKey);
    }
}
#endif