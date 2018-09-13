using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Threading;

namespace JsonWebToken
{
    public abstract class HttpKeyProvider : IKeyProvider, IDisposable
    {
        private readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1);
        private readonly HttpDocumentRetriever _documentRetriever;
        private readonly TimeSpan _refreshInterval = DefaultRefreshInterval;
        private readonly TimeSpan _automaticRefreshInterval = DefaultAutomaticRefreshInterval;
        private DateTimeOffset _syncAfter;
        private JsonWebKeySet _currentKeys;
        private bool _disposed;

        private static readonly JsonWebKey[] Empty = Array.Empty<JsonWebKey>();

        /// <summary>
        /// 1 day is the default time interval that afterwards, <see cref="GetConfigurationAsync()"/> will obtain new configuration.
        /// </summary>
        public static readonly TimeSpan DefaultAutomaticRefreshInterval = new TimeSpan(1, 0, 0, 0);

        /// <summary>
        /// 30 seconds is the default time interval that must pass for <see cref="RequestRefresh"/> to obtain a new configuration.
        /// </summary>
        public static readonly TimeSpan DefaultRefreshInterval = new TimeSpan(0, 0, 0, 30);

        /// <summary>
        /// 5 minutes is the minimum value for automatic refresh. <see cref="AutomaticRefreshInterval"/> can not be set less than this value.
        /// </summary>
        public static readonly TimeSpan MinimumAutomaticRefreshInterval = new TimeSpan(0, 0, 5, 0);

        /// <summary>
        /// 1 second is the minimum time interval that must pass for <see cref="RequestRefresh"/> to obtain new configuration.
        /// </summary>
        public static readonly TimeSpan MinimumRefreshInterval = new TimeSpan(0, 0, 0, 1);

        public HttpKeyProvider(HttpDocumentRetriever documentRetriever)
        {
            _documentRetriever = documentRetriever ?? throw new ArgumentNullException(nameof(documentRetriever));
        }

        public HttpKeyProvider()
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

            _refreshLock.Wait();
            try
            {
                if (_syncAfter <= now)
                {
                    try
                    {
                        var value = _documentRetriever.GetDocument(metadataAddress, CancellationToken.None);
                        _currentKeys = JsonConvert.DeserializeObject<JsonWebKeySet>(value);
                        _syncAfter = DateTimeUtil.Add(now.UtcDateTime, _automaticRefreshInterval);
                    }
                    catch
                    {
                        _syncAfter = DateTimeUtil.Add(now.UtcDateTime, _automaticRefreshInterval < _refreshInterval ? _automaticRefreshInterval : _refreshInterval);
                        throw;
                    }
                }

                if (_currentKeys == null)
                {
                    Errors.ThrowUnableToObtainKeys(metadataAddress);
                }

                return _currentKeys.GetKeys(kid);
            }
            finally
            {
                _refreshLock.Release();
            }
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
