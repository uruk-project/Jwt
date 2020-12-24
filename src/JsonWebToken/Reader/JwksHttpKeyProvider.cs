// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>Represents a <see cref="IKeyProvider"/> that retrieve the key set from an HTTP resource as JWKS.</summary>
    public sealed class JwksHttpKeyProvider : IKeyProvider, IDisposable
    {
        private static ReadOnlySpan<byte> _issuerName => new byte[6] { (byte)'i', (byte)'s', (byte)'s', (byte)'u', (byte)'e', (byte)'r' };
        private static ReadOnlySpan<byte> _jwksUriName => new byte[8] { (byte)'j', (byte)'w', (byte)'k', (byte)'s', (byte)'_', (byte)'u', (byte)'r', (byte)'i' };

        private readonly string _jwksAddress;
        private readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1);
        private readonly HttpDocumentRetriever _documentRetriever;
        private long _syncAfter;
        private Jwks? _currentJwks;
        private bool _disposed;

        /// <summary>1 day is the default time interval that afterwards, <see cref="GetKeys(JwtHeaderDocument, string)"/> will obtain new configuration.</summary>
        public static readonly long DefaultAutomaticRefreshInterval = 60 * 60 * 24;

        /// <summary>30 seconds is the default time interval to obtain a new key set.</summary>
        public static readonly long DefaultRefreshInterval = 30;
        private readonly string _issuer;

        /// <summary>Time interval to obtain a new key set.</summary>  
        public long RefreshInterval { get; set; } = DefaultRefreshInterval;

        /// <summary>Time interval that afterwards, <see cref="GetKeys(JwtHeaderDocument, string)"/> will obtain new configuration.</summary>
        public long AutomaticRefreshInterval { get; set; } = DefaultAutomaticRefreshInterval;

        /// <summary>Gets the http document retriever.</summary>
        private HttpDocumentRetriever DocumentRetriever => _documentRetriever;

        /// <inheritdoc/>
        public string Issuer => _issuer;

        /// <summary>Initializes a new instance of <see cref="JwksHttpKeyProvider"/>.y</summary>
        public JwksHttpKeyProvider(string issuer, string jwksAddress, HttpDocumentRetriever documentRetriever)
        {
            _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            _documentRetriever = documentRetriever ?? throw new ArgumentNullException(nameof(documentRetriever));
            _jwksAddress = jwksAddress ?? throw new ArgumentNullException(nameof(jwksAddress));
        }

        /// <summary>Initializes a new instance of <see cref="JwksHttpKeyProvider"/>.</summary>
        public JwksHttpKeyProvider(string issuer, string jwksAddress, HttpMessageHandler? handler)
            : this(issuer, jwksAddress, new HttpDocumentRetriever(handler))
        {
        }

        /// <summary>Initializes a new instance of <see cref="JwksHttpKeyProvider"/>.y</summary>
        public JwksHttpKeyProvider(string metadataConfiguration, HttpDocumentRetriever documentRetriever)
        {
            if (metadataConfiguration is null)
            {
                throw new ArgumentNullException(nameof(metadataConfiguration));
            }

            if (documentRetriever is null)
            {
                throw new ArgumentNullException(nameof(documentRetriever));
            }

            _documentRetriever = documentRetriever ?? throw new ArgumentNullException(nameof(documentRetriever));
            (_issuer, _jwksAddress) = GetMetadataConfiguration(DocumentRetriever, metadataConfiguration);
        }

        /// <summary>Initializes a new instance of <see cref="JwksHttpKeyProvider"/>.</summary>
        public JwksHttpKeyProvider(string metadataConfiguration, HttpMessageHandler? handler)
            : this(metadataConfiguration, new HttpDocumentRetriever(handler))
        {
        }

        private static (string, string) GetMetadataConfiguration(HttpDocumentRetriever documentRetriever, string metadataAddress)
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
                if (reader.ValueTextEquals(_issuerName))
                {
                    reader.Read();
                    issuer = reader.GetString();
                    if (jwksUri != null)
                    {
                        break;
                    }
                }
                else if (reader.ValueTextEquals(_jwksUriName))
                {
                    reader.Read();
                    jwksUri = reader.GetString();
                    if (issuer != null)
                    {
                        break;
                    }
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
            if (!metadataAddress.StartsWith(issuer))
            {
                throw new InvalidOperationException($"The 'issuer' claim in the document '{metadataAddress}' is invalid.");
            }

            return (issuer, jwksUri);
        }

        /// <summary>Initializes a new instance of <see cref="JwksHttpKeyProvider"/>.</summary>
        public JwksHttpKeyProvider(string metadataAddress)
            : this(metadataAddress, new HttpDocumentRetriever())
        {
        }

        /// <summary>Initializes a new instance of <see cref="JwksHttpKeyProvider"/>.</summary>
        public JwksHttpKeyProvider(string issuer, string jwksAddress)
            : this(issuer, jwksAddress, new HttpDocumentRetriever())
        {
        }

        /// <inheritsdoc />
        public Jwk[] GetKeys(JwtHeaderDocument header)
        {
            return GetKeys(header, _jwksAddress);
        }

        /// <inheritsdoc />
        private Jwk[] GetKeys(JwtHeaderDocument header, string metadataAddress)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(typeof(JwksHttpKeyProvider));
            }

            var kid = header.Kid;
            long now = EpochTime.UtcNow;
            if (_currentJwks != null && _syncAfter > now)
            {
                return _currentJwks.GetKeys(kid);
            }

            if (_syncAfter <= now)
            {
                _refreshLock.Wait();
                try
                {
                    var value = _documentRetriever.GetDocument(metadataAddress, CancellationToken.None);
                    var refreshedJwks = Jwks.FromJson(Issuer, value);
                    Jwks.PublishJwksRefreshed(refreshedJwks);
                    _currentJwks = refreshedJwks;
                    _syncAfter = now + AutomaticRefreshInterval;
                }
                catch
                {
                    _syncAfter = now + (AutomaticRefreshInterval < RefreshInterval ? AutomaticRefreshInterval : RefreshInterval);
                    throw;
                }
                finally
                {
                    _refreshLock.Release();
                }
            }

            if (_currentJwks != null)
            {
                return _currentJwks.GetKeys(kid);
            }

            ThrowHelper.ThrowInvalidOperationException_UnableToObtainKeysException(metadataAddress);
            return Array.Empty<Jwk>();
        }

        /// <summary>Disposes the managed resources.</summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                _refreshLock.Dispose();
                _documentRetriever.Dispose();
                _currentJwks?.Dispose();
                _disposed = true;
            }
        }
    }
}
