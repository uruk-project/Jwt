// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Net.Http;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a <see cref="IKeyProvider"/> that retrieve the key set with the 'jwk' header parameter.
    /// </summary>
    public sealed class JwksKeyProvider : HttpKeyProvider
    {
        private readonly string _jwksAddress;

        /// <summary>
        /// Initializes a new instance of <see cref="JwksKeyProvider"/>.
        /// </summary>
        /// <param name="jwksAddress"></param>
        /// <param name="documentRetriever"></param>
        public JwksKeyProvider(string jwksAddress, HttpDocumentRetriever documentRetriever)
            : base(documentRetriever)
        {
            _jwksAddress = jwksAddress ?? throw new System.ArgumentNullException(nameof(jwksAddress));
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwksKeyProvider"/>.
        /// </summary>
        /// <param name="jwksAddress"></param>
        /// <param name="handler"></param>
        public JwksKeyProvider(string jwksAddress, HttpMessageHandler? handler)
            : base(new HttpDocumentRetriever(handler))
        {
            _jwksAddress = jwksAddress ?? throw new System.ArgumentNullException(nameof(jwksAddress));
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwksKeyProvider"/>.
        /// </summary>
        /// <param name="metadataAddress"></param>
        public JwksKeyProvider(string metadataAddress)
            : this(metadataAddress, new HttpDocumentRetriever())
        {
        }

        /// <inheritsdoc />
        public override Jwk[] GetKeys(JwtHeader header)
        {
            return GetKeys(header, _jwksAddress);
        }

        /// <inheritsdoc />
        public override Jwk[] GetKeys(JwtHeaderDocument2 header)
        {
            return GetKeys(header, _jwksAddress);
        }

        /// <inheritsdoc />
        public override Jwk[] GetKeys(JwtHeaderDocument header)
        {
            return GetKeys(header, _jwksAddress);
        }

        /// <inheritsdoc />
        protected override Jwks DeserializeKeySet(string value)
        {
            return Jwks.FromJson(value);
        }
    }
}
