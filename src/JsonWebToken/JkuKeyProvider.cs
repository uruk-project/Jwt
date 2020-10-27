// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Text.Json;
using JsonWebToken.Internal;

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
        public override Jwk[] GetKeys(JwtHeader header)
        {
            if (header is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.header);
            }

            if (header.Jku is null)
            {
                return Array.Empty<Jwk>();
            }

            return GetKeys(header, header.Jku);
        }

        /// <inheritsdoc />
        public override Jwk[] GetKeys(JwtHeaderDocument header)
        {
            if (header is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.header);
            }

            if (!header.TryGetHeaderParameter(HeaderParameters.JkuUtf8, out var jku))
            {
                return Array.Empty<Jwk>();
            }

            var jkuValue = jku.GetString();
            if (jkuValue is null)
            {
                return Array.Empty<Jwk>();
            }

            return GetKeys(header, jkuValue);
        }

        /// <inheritsdoc />
        protected override Jwks DeserializeKeySet(string value)
        {
            return Jwks.FromJson(value);
        }
    }
}
