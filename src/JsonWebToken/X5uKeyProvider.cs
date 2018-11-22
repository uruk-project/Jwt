// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace JsonWebToken
{
    public sealed class X5uKeyProvider : HttpKeyProvider
    {
        public X5uKeyProvider(HttpDocumentRetriever documentRetriever)
            : base(documentRetriever)
        {
        }

        /// <inheritsdoc />
        public override IReadOnlyList<Jwk> GetKeys(JwtHeader header)
        {
            return GetKeys(header, header.X5u);
        }

        /// <inheritsdoc />
        protected override Jwks DeserializeKeySet(string value)
        {
            using (var certificate = new X509Certificate2(Convert.FromBase64String(value)))
            {
                return new Jwks(new[] { ConvertFromX509(certificate) });
            }
        }

        private static RsaJwk ConvertFromX509(X509Certificate2 certificate)
        {
            var key = new RsaJwk
            {
                Kty = JwkTypeNames.Rsa,
                Kid = certificate.Thumbprint,
                X5t = Base64Url.Base64UrlEncode(certificate.GetCertHash())
            };
            if (certificate.RawData != null)
            {
                key.X5c.Add(Convert.ToBase64String(certificate.RawData));
            }

            return key;
        }
    }
}