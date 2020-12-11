﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>Defines a <see cref="IKeyProvider"/> that gets the keys from and HTTP endpoint.</summary>
    public abstract class HttpKeyProvider : IKeyProvider, IDisposable
    {
        private readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1);
        private readonly HttpDocumentRetriever _documentRetriever;
        private long _syncAfter;
        private Jwks? _currentJwks;
        private bool _disposed;

        /// <summary>1 day is the default time interval that afterwards, <see cref="GetKeys(JwtHeaderDocument, string)"/> will obtain new configuration.</summary>
        public static readonly long DefaultAutomaticRefreshInterval = 60 * 60 * 24;

        /// <summary>30 seconds is the default time interval to obtain a new key set.</summary>
        public static readonly long DefaultRefreshInterval = 30;

        /// <summary>Time interval to obtain a new key set.</summary>  
        public long RefreshInterval { get; set; } = DefaultRefreshInterval;

        /// <summary>Time interval that afterwards, <see cref="GetKeys(JwtHeaderDocument, string)"/> will obtain new configuration.</summary>
        public long AutomaticRefreshInterval { get; set; } = DefaultAutomaticRefreshInterval;

        /// <summary>Gets the http document retriever.</summary>
        protected HttpDocumentRetriever DocumentRetriever => _documentRetriever;

        /// <summary>Initializes a new instance of <see cref="HttpKeyProvider"/>.</summary>
        /// <param name="documentRetriever"></param>
        protected HttpKeyProvider(HttpDocumentRetriever documentRetriever)
        {
            _documentRetriever = documentRetriever ?? throw new ArgumentNullException(nameof(documentRetriever));
        }

        /// <summary>Initializes a new instance of <see cref="HttpKeyProvider"/>.</summary>
        protected HttpKeyProvider()
            : this(new HttpDocumentRetriever())
        {
        }

        /// <inheritsdoc />
        public abstract Jwk[] GetKeys(JwtHeaderDocument header);

        /// <summary>Deserializes a JSON string representing a JWKS.</summary>
        /// <param name="value"></param>
        /// <returns></returns>
        protected abstract Jwks DeserializeKeySet(string value);

        /// <inheritsdoc />
        protected Jwk[] GetKeys(JwtHeaderDocument header, string metadataAddress)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(typeof(HttpKeyProvider));
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
                    var refreshedJwks = Jwks.FromJson(value);
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
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _refreshLock.Dispose();
                    _documentRetriever.Dispose();
                    _currentJwks?.Dispose();
                }

                _disposed = true;
            }
        }

        /// <summary>Disposes the managed resources.</summary>
        public void Dispose()
        {
            GC.SuppressFinalize(this);
            Dispose(true);
        }
    }
}
