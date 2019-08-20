// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Net.Http;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>
    /// Retrieves metadata information using <see cref="HttpClient"/>.
    /// </summary>
    public sealed class HttpDocumentRetriever : IDisposable
    {
        private readonly HttpClient _httpClient;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpDocumentRetriever"/> class.
        /// </summary>
        public HttpDocumentRetriever()
            : this(null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpDocumentRetriever"/> class with a specified httpClient.
        /// </summary>
        /// <param name="handler"><see cref="HttpMessageHandler"/></param>
        public HttpDocumentRetriever(HttpMessageHandler? handler)
        {
            _httpClient = new HttpClient(handler ?? new HttpClientHandler());
        }

        /// <summary>
        /// Requires Https secure channel for sending requests.. This is turned ON by default for security reasons. It is RECOMMENDED that you do not allow retrieval from http addresses by default.
        /// </summary>
        public bool RequireHttps { get; set; } = true;

        /// <summary>
        /// Returns a task which contains a string converted from remote document when completed, by using the provided address.
        /// </summary>
        /// <param name="address">Location of document</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation. <see cref="CancellationToken"/></param>
        /// <returns>Document as a string</returns>
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

            using (HttpResponseMessage response = _httpClient.GetAsync(address, cancellationToken).ConfigureAwait(false).GetAwaiter().GetResult().EnsureSuccessStatusCode())
            {
                return response.Content.ReadAsByteArrayAsync().ConfigureAwait(false).GetAwaiter().GetResult();
            }
        }

        /// <summary>
        /// Release managed resources.
        /// </summary>
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
            if (string.IsNullOrEmpty(address))
            {
                return false;
            }

            try
            {
                Uri uri = new Uri(address);
                return IsHttps(uri);
            }
            catch (UriFormatException)
            {
                return false;
            }
        }

        private static bool IsHttps(Uri uri)
        {
            return uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
        }
    }
}
