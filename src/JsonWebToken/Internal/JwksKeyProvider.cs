// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net.Http;

namespace JsonWebToken.Internal
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

        public override IReadOnlyList<JsonWebKey> GetKeys(JwtHeader header)
        {
            return GetKeys(header, _jwksAddress);
        }

        protected override JsonWebKeySet DeserializeKeySet(string value)
        {
            return JsonConvert.DeserializeObject<JsonWebKeySet>(value);
        }
    }
}
