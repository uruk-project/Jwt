// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a <see cref="IKeyProvider"/> that retrieve the key set with the 'jwk' header parameter.
    /// </summary>
    public sealed class JwksKeyProvider : HttpKeyProvider
    {
        private readonly string? _metadataAddress;
        private readonly string _jwksAddress;
        private readonly MetadataRetrievalBehavior _behavior;

        /// <summary>
        /// Initializes a new instance of <see cref="JwksKeyProvider"/>.
        /// </summary>
        /// <param name="jwksAddress"></param>
        /// <param name="documentRetriever"></param>
        /// <param name="behavior">Defines the behavior for retrieving the JWKS document.</param>
        public JwksKeyProvider(string jwksAddress, HttpDocumentRetriever documentRetriever, MetadataRetrievalBehavior behavior = MetadataRetrievalBehavior.FromJwksUrl)
            : base(documentRetriever)
        {
            _jwksAddress = jwksAddress ?? throw new ArgumentNullException(nameof(jwksAddress));
            _behavior = behavior;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwksKeyProvider"/>.
        /// </summary>
        /// <param name="jwksAddress"></param>
        /// <param name="handler"></param>
        /// <param name="behavior">Defines the behavior for retrieving the JWKS document.</param>
        public JwksKeyProvider(string jwksAddress, HttpMessageHandler? handler, MetadataRetrievalBehavior behavior = MetadataRetrievalBehavior.FromJwksUrl)
            : base(new HttpDocumentRetriever(handler))
        {
            if (jwksAddress is null)
            {
                throw new ArgumentNullException(nameof(jwksAddress));
            }

            _metadataAddress = jwksAddress;
            _jwksAddress = behavior == MetadataRetrievalBehavior.FromJwksUrl ? jwksAddress : GetMetadataConfiguration(DocumentRetriever, jwksAddress);
            _behavior = behavior;
        }

        private static string GetMetadataConfiguration(HttpDocumentRetriever documentRetriever, string metadataAddress)
        {
            string? issuer = null;
            string? jwksUri = null;
            var config = documentRetriever.GetDocument(metadataAddress, CancellationToken.None);
            var reader = new Utf8JsonReader(config);
            if (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
            {
                while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
                {
                    if (reader.ValueTextEquals("issuer"))
                    {
                        reader.Read();
                        issuer = reader.GetString();
                        if (jwksUri != null)
                        {
                            break;
                        }
                    }
                    else if (reader.ValueTextEquals("jwks_uri"))
                    {
                        reader.Read();
                        jwksUri = reader.GetString();
                        if (issuer != null)
                        {
                            break;
                        }
                    }
                }
            }
            else
            {
                throw new InvalidOperationException($"Invalid JSON document at '{metadataAddress}'.");
            }

            if (jwksUri is null)
            {
                throw new InvalidOperationException($"Invalid JSON document at '{metadataAddress}'. No 'jwks_uri' claim found.");
            }
            
            if (issuer is null)
            {
                throw new InvalidOperationException($"Invalid JSON document at '{metadataAddress}'. No 'issuer' claim found.");
            }

            // Not perfect as test, but we do not have the issuer here for the moment.
            if (!metadataAddress.StartsWith(issuer))
            {
                throw new InvalidOperationException($"The 'issuer' claim in the document '{metadataAddress}' is invalid.");
            }

            return jwksUri;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwksKeyProvider"/>.
        /// </summary>
        /// <param name="metadataAddress"></param>
        /// <param name="behavior">Defines the behavior for retrieving the JWKS document.</param>
        public JwksKeyProvider(string metadataAddress, MetadataRetrievalBehavior behavior = MetadataRetrievalBehavior.FromJwksUrl)
            : this(metadataAddress, new HttpDocumentRetriever(), behavior)
        {
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

    /// <summary>
    /// Represents the 
    /// </summary>
    public enum MetadataRetrievalBehavior
    {
        /// <summary>
        /// The JWKS document will be retrieve directly from the JWKS URL.
        /// </summary>
        FromJwksUrl,

        /// <summary>
        /// The metadata document will be retrieve from the url, then the JWKS document will be retrieve from the jwks_uri JSON member.
        /// </summary>
        FromMetadataUrl
    }
}
