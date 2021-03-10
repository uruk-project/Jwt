// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>Represents a <see cref="IKeyProvider"/> with cache management.</summary>
    public abstract class CachedKeyProvider : IKeyProvider, IDisposable
    {
        private readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1);
        private long _syncAfter;
        private long _forcedSyncAfter;
        private Jwks _currentJwks;
        private bool _disposed;

        private static readonly Jwks EmptyJwks = new Jwks();

        /// <summary>The issuer of the keys.</summary>
        public abstract string Issuer { get; }

        /// <summary>1 day is the default time interval that afterwards, <see cref="GetKeys(JwtHeaderDocument)"/> will obtain new configuration.</summary>
        public const long DefaultAutomaticRefreshInterval = 60 * 60 * 24;

        /// <summary>60 seconds is the default time interval to obtain a new key set.</summary>
        public const long DefaultMinimumRefreshInterval = 60;

        /// <summary>Time interval to obtain a new key set.</summary>  
        public long MinimumRefreshInterval { get; }

        /// <summary>Time interval that afterwards, <see cref="GetKeys(JwtHeaderDocument)"/> will obtain new configuration.</summary>
        public long AutomaticRefreshInterval { get; }

        /// <summary>Initializes a new instance of <see cref="CachedKeyProvider"/> class.</summary>
        protected CachedKeyProvider(long minimumRefreshInterval = DefaultMinimumRefreshInterval, long automaticRefreshInterval = DefaultAutomaticRefreshInterval)
        {
            _currentJwks = EmptyJwks;
            MinimumRefreshInterval = minimumRefreshInterval;
            AutomaticRefreshInterval = automaticRefreshInterval;
        }

        /// <inheritsdoc />
        public Jwk[] GetKeys(JwtHeaderDocument header)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(typeof(CachedKeyProvider));
            }

            var kid = header.Kid;
            long now = EpochTime.UtcNow;
            bool forceSync = false;
            if (_syncAfter > now)
            {
                var keys = _currentJwks.GetKeys(kid);
                if (keys.Length != 0)
                {
                    return keys;
                }

                // force the refresh only when the latest forced refresh is not too old
                if (_forcedSyncAfter <= now)
                {
                    _forcedSyncAfter = now + MinimumRefreshInterval;
                    forceSync = true;
                }
            }

            if (forceSync || _syncAfter <= now)
            {
                _refreshLock.Wait();
                try
                {
                    Jwks refreshedJwks = GetKeysFromSource();
                    Jwks.PublishJwksRefreshed(refreshedJwks);
                    _currentJwks = refreshedJwks;
                    _syncAfter = now + AutomaticRefreshInterval;
                }
                catch
                {
                    _syncAfter = now + Math.Min(AutomaticRefreshInterval, MinimumRefreshInterval);
                    throw;
                }
                finally
                {
                    _refreshLock.Release();
                }
            }

            return _currentJwks.GetKeys(kid);
        }

        /// <summary>Gets the keys from its source.</summary>
        /// <returns></returns>
        protected abstract Jwks GetKeysFromSource();

        /// <summary>Disposes the managed resources.</summary>
        public virtual void Dispose()
        {
            if (!_disposed)
            {
                _refreshLock.Dispose();
                _currentJwks.Dispose();
                _disposed = true;
            }
        }

        /// <inheritdoc />
        public virtual void ForceRefresh()
        {
            _syncAfter = 0;
        }
    }
}
