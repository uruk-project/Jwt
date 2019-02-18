// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Security.Cryptography.X509Certificates;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a <see cref="IKeyProvider"/> that retrieve key set with the 'x5u' header parameter.
    /// </summary>
    public sealed class X5uKeyProvider : HttpKeyProvider
    {
        /// <summary>
        /// Initializes a new instance of <see cref="X5uKeyProvider"/>.
        /// </summary>
        /// <param name="documentRetriever"></param>
        public X5uKeyProvider(HttpDocumentRetriever documentRetriever)
            : base(documentRetriever)
        {
        }

        /// <inheritsdoc />
        public override Jwk[] GetKeys(JwtHeader header)
        {
            return GetKeys(header, header.X5u);
        }

        /// <inheritsdoc />
        protected override Jwks DeserializeKeySet(string value)
        {
            using (var certificate = new X509Certificate2(Convert.FromBase64String(value)))
            {
                return new Jwks(new[] { Jwk.FromX509Certificate(certificate, false) });
            }
        }
    }
}