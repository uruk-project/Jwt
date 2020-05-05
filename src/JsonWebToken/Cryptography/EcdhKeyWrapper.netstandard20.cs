// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if !NETCOREAPP && !NET47
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
