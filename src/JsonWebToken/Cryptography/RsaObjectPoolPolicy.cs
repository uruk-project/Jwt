// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    internal sealed class RsaObjectPoolPolicy : PooledObjectFactory<RSA>
    {
        private readonly RSAParameters _parameters;

        public RsaObjectPoolPolicy(RSAParameters parameters)
        {
            _parameters = parameters;
        }

        public override RSA Create()
        {
#if SUPPORT_SPAN_CRYPTO
            return RSA.Create(_parameters);
#else
#if NET462 || NET47
            var rsa = new RSACng();
#else
            var rsa = RSA.Create();
#endif
            rsa.ImportParameters(_parameters);
            return rsa;
#endif
        }
    }
}