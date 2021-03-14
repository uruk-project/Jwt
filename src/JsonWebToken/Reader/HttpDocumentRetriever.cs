// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Net.Http;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>Retrieves metadata information using <see cref="HttpClient"/>.</summary>
    public sealed class HttpDocumentRetriever : IDisposable
    {
        private readonly HttpClient _httpClient;
        private bool _disposed;

        /// <summary>Initializes a new instance of the <see cref="HttpDocumentRetriever"/> class.</summary>
        public HttpDocumentRetriever()
            : this(new HttpClientHandler())
        {
        }

        /// <summary>Initializes a new instance of the <see cref="HttpDocumentRetriever"/> class with a specified httpClient.</summary>
        /// <param name="handler"><see cref="HttpMessageHandler"/></param>
        public HttpDocumentRetriever(HttpMessageHandler handler)
        {
            _httpClient = new HttpClient(handler ?? throw new ArgumentNullException(nameof(handler)));
        }

        /// <summary>Requires Https secure channel for sending requests. This is turned ON by default for security reasons. It is RECOMMENDED that you do not allow retrieval from http addresses by default.</summary>
        public bool RequireHttps { get; set; } = true;

        /// <summary>Returns a task which contains a string converted from remote document when completed, by using the provided address.</summary>
        /// <param name="address">Location of document</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation. <see cref="CancellationToken"/></param>
        /// <returns>Document as a byte array.</returns>
        public byte[] GetDocument(string address, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentNullException(nameof(address));
            }

            if (!IsHttps(address) && RequireHttps)
            {
                ThrowHelper.ThrowArgumentException_RequireHttpsException(address);
            }

            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            using HttpResponseMessage response = _httpClient.GetAsync(address, cancellationToken).ConfigureAwait(false).GetAwaiter().GetResult().EnsureSuccessStatusCode();
#if NET5_0
            return response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false).GetAwaiter().GetResult();
#else
            return response.Content.ReadAsByteArrayAsync().ConfigureAwait(false).GetAwaiter().GetResult();
#endif
        }

        /// <summary>Release managed resources.</summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                _httpClient.Dispose();
                _disposed = true;
            }
        }

        private static bool IsHttps(string address)
        {
            try
            {
                Uri uri = new Uri(address);
                return uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
            }
            catch (UriFormatException)
            {
                return false;
            }
        }
    }
}
