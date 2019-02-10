// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a <see cref="IKeyProvider"/> that retrieve the key set with the 'jku' header parameter.
    /// </summary>
    public sealed class JkuKeyProvider : HttpKeyProvider
    {
        /// <summary>
        /// Initializes a new instance of <see cref="JkuKeyProvider"/>.
        /// </summary>
        /// <param name="documentRetriever"></param>
        public JkuKeyProvider(HttpDocumentRetriever documentRetriever)
            : base(documentRetriever)
        {
        }

        /// <inheritsdoc />
        public override IReadOnlyList<Jwk> GetKeys(JwtHeader header)
        {
            return GetKeys(header, header.Jku);
        }

        /// <inheritsdoc />
        protected override Jwks DeserializeKeySet(string value)
        {
            return Jwks.FromJson(value);
        }
    }
}
