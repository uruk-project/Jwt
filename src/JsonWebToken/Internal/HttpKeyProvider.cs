// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Threading;

namespace JsonWebToken.Internal
{
    public abstract class HttpKeyProvider : IKeyProvider, IDisposable
    {
        private readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1);
        private readonly HttpDocumentRetriever _documentRetriever;
        private readonly long _refreshInterval = DefaultRefreshInterval;
        private readonly long _automaticRefreshInterval = DefaultAutomaticRefreshInterval;
        private DateTimeOffset _syncAfter;
        private JsonWebKeySet _currentKeys;
        private bool _disposed;

        /// <summary>
        /// 1 day is the default time interval that afterwards, <see cref="GetConfigurationAsync()"/> will obtain new configuration.
        /// </summary>
        public static readonly long DefaultAutomaticRefreshInterval = TimeSpan.TicksPerDay;

        /// <summary>
        /// 30 seconds is the default time interval that must pass for <see cref="RequestRefresh"/> to obtain a new configuration.
        /// </summary>
        public static readonly long DefaultRefreshInterval = 30 * TimeSpan.TicksPerSecond;

        /// <summary>
        /// 5 minutes is the minimum value for automatic refresh. <see cref="AutomaticRefreshInterval"/> can not be set less than this value.
        /// </summary>
        public static readonly long MinimumAutomaticRefreshInterval = 5 * TimeSpan.TicksPerMinute;

        /// <summary>
        /// 1 second is the minimum time interval that must pass for <see cref="RequestRefresh"/> to obtain new configuration.
        /// </summary>
        public static readonly long MinimumRefreshInterval = TimeSpan.TicksPerSecond;

        protected HttpKeyProvider(HttpDocumentRetriever documentRetriever)
        {
            _documentRetriever = documentRetriever ?? throw new ArgumentNullException(nameof(documentRetriever));
        }

        protected HttpKeyProvider()
            : this(new HttpDocumentRetriever())
        {
        }

        public abstract IReadOnlyList<JsonWebKey> GetKeys(JwtHeader header);

        protected abstract JsonWebKeySet DeserializeKeySet(string value);

        protected IReadOnlyList<JsonWebKey> GetKeys(JwtHeader header, string metadataAddress)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            var kid = header.Kid;
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (_currentKeys != null && _syncAfter > now)
            {
                return _currentKeys.GetKeys(kid);
            }

            if (_syncAfter <= now)
            {
                _refreshLock.Wait();
                try
                {
                    var value = _documentRetriever.GetDocument(metadataAddress, CancellationToken.None);
                    _currentKeys = JsonConvert.DeserializeObject<JsonWebKeySet>(value);
                    _syncAfter = now.UtcDateTime.AddSafe(_automaticRefreshInterval);
                }
                catch
                {
                    _syncAfter = now.UtcDateTime.AddSafe(_automaticRefreshInterval < _refreshInterval ? _automaticRefreshInterval : _refreshInterval);
                    throw;
                }
                finally
                {
                    _refreshLock.Release();
                }
            }

            if (_currentKeys == null)
            {
                Errors.ThrowUnableToObtainKeys(metadataAddress);
            }

            return _currentKeys.GetKeys(kid);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _refreshLock.Dispose();
                    _documentRetriever.Dispose();
                }

                _disposed = true;
            }
        }

        public void Dispose()
        {
            GC.SuppressFinalize(this);
            Dispose(true);
        }
    }
}
