// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>Represents a <see cref="IKeyProvider"/> that retrieve the key set from an HTTP resource as JWKS.</summary>
    public sealed class JwksHttpKeyProvider : CachedKeyProvider
    {
        private static ReadOnlySpan<byte> IssuerName => new byte[6] { (byte)'i', (byte)'s', (byte)'s', (byte)'u', (byte)'e', (byte)'r' };
        private static ReadOnlySpan<byte> JwksUriName => new byte[8] { (byte)'j', (byte)'w', (byte)'k', (byte)'s', (byte)'_', (byte)'u', (byte)'r', (byte)'i' };

        private readonly string _issuer;
        private readonly Func<HttpDocumentRetriever> _documentRetrieverFactory;
        private readonly string _jwksAddress;

        /// <inheritdoc/>
        public override string Issuer => _issuer;

        /// <summary>Initializes a new instance of <see cref="JwksHttpKeyProvider"/>.y</summary>
        public JwksHttpKeyProvider(string issuer, string jwksAddress, Func<HttpDocumentRetriever> documentRetrieverFactory, long minimumRefreshInterval = DefaultMinimumRefreshInterval, long automaticRefreshInterval = DefaultAutomaticRefreshInterval)
            : base(minimumRefreshInterval, automaticRefreshInterval)
        {
            _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            _documentRetrieverFactory = documentRetrieverFactory ?? throw new ArgumentNullException(nameof(documentRetrieverFactory));
            _jwksAddress = jwksAddress ?? throw new ArgumentNullException(nameof(jwksAddress));
        }

        /// <summary>Initializes a new instance of <see cref="JwksHttpKeyProvider"/> class.</summary>
        public JwksHttpKeyProvider(string issuer, string jwksAddress, HttpMessageHandler? handler, long minimumRefreshInterval = DefaultMinimumRefreshInterval, long automaticRefreshInterval = DefaultAutomaticRefreshInterval)
            : this(issuer, jwksAddress, () => new HttpDocumentRetriever(handler), minimumRefreshInterval, automaticRefreshInterval)
        {
        }

        /// <summary>Initializes a new instance of <see cref="JwksHttpKeyProvider"/> class.</summary>
        public JwksHttpKeyProvider(string metadataConfiguration, Func<HttpDocumentRetriever> documentRetrieverFactory, long minimumRefreshInterval = DefaultMinimumRefreshInterval, long automaticRefreshInterval = DefaultAutomaticRefreshInterval, bool validateIssuer = true)
            : base(minimumRefreshInterval, automaticRefreshInterval)
        {
            if (metadataConfiguration is null)
            {
                throw new ArgumentNullException(nameof(metadataConfiguration));
            }

            if (documentRetrieverFactory is null)
            {
                throw new ArgumentNullException(nameof(documentRetrieverFactory));
            }

            _documentRetrieverFactory = documentRetrieverFactory ?? throw new ArgumentNullException(nameof(documentRetrieverFactory));
            using var retriever = _documentRetrieverFactory();
            (_issuer, _jwksAddress) = GetMetadataConfiguration(retriever, metadataConfiguration, validateIssuer);
        }

        /// <summary>Initializes a new instance of <see cref="JwksHttpKeyProvider"/>.</summary>
        public JwksHttpKeyProvider(string metadataConfiguration, HttpMessageHandler? handler, long minimumRefreshInterval = DefaultMinimumRefreshInterval, long automaticRefreshInterval = DefaultAutomaticRefreshInterval, bool validateIssuer = true)
            : this(metadataConfiguration, () => new HttpDocumentRetriever(handler), minimumRefreshInterval, automaticRefreshInterval, validateIssuer)
        {
        }

        /// <inheritdoc/>
        protected override Jwks GetKeysFromSource()
        {
            using var retriever = _documentRetrieverFactory();
            var value = retriever.GetDocument(_jwksAddress, CancellationToken.None);
            return Jwks.FromJson(Issuer, value);
        }

        private static (string, string) GetMetadataConfiguration(HttpDocumentRetriever documentRetriever, string metadataAddress, bool validateIssuer)
        {
            string? issuer = null;
            string? jwksUri = null;
            var config = documentRetriever.GetDocument(metadataAddress, CancellationToken.None);
            var reader = new Utf8JsonReader(config);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                throw new InvalidOperationException($"Invalid JSON document at '{metadataAddress}'.");
            }

            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                if (reader.ValueTextEquals(IssuerName))
                {
                    reader.Read();
                    issuer = reader.GetString();
                    if (jwksUri != null)
                    {
                        break;
                    }
                }
                else if (reader.ValueTextEquals(JwksUriName))
                {
                    reader.Read();
                    jwksUri = reader.GetString();
                    if (issuer != null)
                    {
                        break;
                    }
                }
                else
                {
                    JsonParser.ConsumeJsonMember(ref reader);
                }
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
            if (validateIssuer && !metadataAddress.StartsWith(issuer))
            {
                throw new InvalidOperationException($"The 'issuer' claim in the document '{metadataAddress}' is invalid.");
            }

            return (issuer, jwksUri);
        }

        /// <summary>Initializes a new instance of <see cref="JwksHttpKeyProvider"/>.</summary>
        public JwksHttpKeyProvider(string metadataAddress, long minimumRefreshInterval = DefaultMinimumRefreshInterval, long automaticRefreshInterval = DefaultAutomaticRefreshInterval, bool validateIssuer = true)
            : this(metadataAddress, () => new HttpDocumentRetriever(), minimumRefreshInterval, automaticRefreshInterval, validateIssuer)
        {
        }

        /// <summary>Initializes a new instance of <see cref="JwksHttpKeyProvider"/>.</summary>
        public JwksHttpKeyProvider(string issuer, string jwksAddress, long minimumRefreshInterval = DefaultMinimumRefreshInterval, long automaticRefreshInterval = DefaultAutomaticRefreshInterval)
            : this(issuer, jwksAddress, () => new HttpDocumentRetriever(), minimumRefreshInterval, automaticRefreshInterval)
        {
        }
    }
}
