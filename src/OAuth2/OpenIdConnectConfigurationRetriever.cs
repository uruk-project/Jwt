// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Net.Http;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>
    ///  Retrieves a populated <see cref="OpenIdConnectConfiguration"/> given an address.
    /// </summary>
    public sealed class OpenIdConnectConfigurationRetriever : IConfigurationRetriever<OpenIdConnectConfiguration>
    {
        /// <summary>
        /// Retrieves a populated <see cref="OpenIdConnectConfiguration"/> given an address.
        /// </summary>
        /// <param name="address">address of the discovery document.</param>
        /// <returns>A populated <see cref="OpenIdConnectConfiguration"/> instance.</returns>
        public static OpenIdConnectConfiguration Get(string address, CancellationToken cancellationToken)
        {
            return Get(address, new HttpDocumentRetriever(), cancellationToken);
        }

        /// <summary>
        /// Retrieves a populated <see cref="OpenIdConnectConfiguration"/> given an address and an <see cref="HttpClient"/>.
        /// </summary>
        /// <param name="address">address of the discovery document.</param>
        /// <param name="httpClient">the <see cref="HttpClient"/> to use to read the discovery document.</param>
        /// <returns>A populated <see cref="OpenIdConnectConfiguration"/> instance.</returns>
        public static OpenIdConnectConfiguration Get(string address, HttpClientHandler httpClient, CancellationToken cancellationToken)
        {
            return Get(address, new HttpDocumentRetriever(httpClient), cancellationToken);
        }

        /// <summary>
        /// Retrieves a populated <see cref="OpenIdConnectConfiguration"/> given an address and an <see cref="DocumentRetriever"/>.
        /// </summary>
        /// <param name="address">address of the discovery document.</param>
        /// <param name="retriever">the <see cref="DocumentRetriever"/> to use to read the discovery document</param>
        /// <returns>A populated <see cref="OpenIdConnectConfiguration"/> instance.</returns>
        public static OpenIdConnectConfiguration Get(string address, HttpDocumentRetriever retriever, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentNullException(nameof(address));
            }

            if (retriever == null)
            {
                throw new ArgumentNullException(nameof(retriever));
            }

            var doc = retriever.GetDocument(address, cancellationToken);
            OpenIdConnectConfiguration openIdConnectConfiguration = OpenIdConnectConfiguration.FromJson(doc);
            return openIdConnectConfiguration;
        }

        public OpenIdConnectConfiguration GetConfiguration(string address, HttpDocumentRetriever retriever, CancellationToken cancellationToken)
        {
            return Get(address, retriever, cancellationToken);
        }
    }
}
