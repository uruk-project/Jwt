using System;
using System.Net.Http;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>
    /// Retrieves metadata information using HttpClient.
    /// </summary>
    public class HttpDocumentRetriever
    {
        private readonly HttpClient _httpClient;

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
        public HttpDocumentRetriever(HttpMessageHandler handler)
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
        public string GetDocument(string address, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentNullException(nameof(address));
            }

            if (!IsHttps(address) && RequireHttps)
            {
                Errors.ThrowRequireHttps(address);
            }

            using (HttpResponseMessage response = _httpClient.GetAsync(address, cancellationToken).ConfigureAwait(false).GetAwaiter().GetResult().EnsureSuccessStatusCode())
            {
                return response.Content.ReadAsStringAsync().ConfigureAwait(false).GetAwaiter().GetResult();
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
