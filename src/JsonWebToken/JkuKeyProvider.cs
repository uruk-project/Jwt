// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json;
using System.Collections.Generic;

namespace JsonWebToken
{
    public sealed class JkuKeyProvider : HttpKeyProvider
    {
        public JkuKeyProvider(HttpDocumentRetriever documentRetriever)
            : base(documentRetriever)
        {
        }

        /// <inheritsdoc />
        public override IReadOnlyList<JsonWebKey> GetKeys(JwtHeader header)
        {
            return GetKeys(header, header.Jku);
        }

        /// <inheritsdoc />
        protected override JsonWebKeySet DeserializeKeySet(string value)
        {
            return JsonConvert.DeserializeObject<JsonWebKeySet>(value);
        }
    }
}
