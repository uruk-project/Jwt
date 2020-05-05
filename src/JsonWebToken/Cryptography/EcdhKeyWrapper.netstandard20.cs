// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if NETSTANDARD2_0 || NET461 || NET47
// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken.Internal
{
    internal sealed class EcdhKeyWrapper : KeyWrapper
    {
        public EcdhKeyWrapper(Jwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(key, encryptionAlgorithm, algorithm)
        {
        }

        public override int GetKeyWrapSize() 
            => throw new NotImplementedException();

        public override Jwk WrapKey(Jwk? staticKey, JwtObject header, Span<byte> destination) 
            => throw new NotImplementedException();

        protected override void Dispose(bool disposing)
        {
        }
    }
}
#endif
