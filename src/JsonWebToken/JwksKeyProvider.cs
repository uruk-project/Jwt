// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net.Http;

namespace JsonWebToken
{
    public sealed class JwksKeyProvider : HttpKeyProvider
    {
        private readonly string _jwksAddress;

        public JwksKeyProvider(string jwksAddress, HttpDocumentRetriever documentRetriever)
            : base(documentRetriever)
        {
            _jwksAddress = jwksAddress ?? throw new System.ArgumentNullException(nameof(jwksAddress));
        }

        public JwksKeyProvider(string jwksAddress, HttpMessageHandler handler)
            : base(new HttpDocumentRetriever(handler))
        {
            _jwksAddress = jwksAddress ?? throw new System.ArgumentNullException(nameof(jwksAddress));
        }

        public JwksKeyProvider(string metadataAddress)
            : this(metadataAddress, new HttpDocumentRetriever())
        {
        }

        /// <inheritsdoc />
        public override IReadOnlyList<Jwk> GetKeys(JwtHeader header)
        {
            return GetKeys(header, _jwksAddress);
        }

        /// <inheritsdoc />
        protected override Jwks DeserializeKeySet(string value)
        {
            return JsonConvert.DeserializeObject<Jwks>(value);
        }
    }
}
