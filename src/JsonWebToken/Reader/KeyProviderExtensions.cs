// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Provides extensions methods to <see cref="IKeyProvider"/>.</summary>
    public static class KeyProviderExtensions
    {
        /// <summary>Gets a list of <see cref="Jwk"/>.</summary>
        public static Jwk[] GetKeys(this IKeyProvider provider)
        {
            return provider.GetKeys(JwtHeaderDocument.Empty);
        }
    }
}
