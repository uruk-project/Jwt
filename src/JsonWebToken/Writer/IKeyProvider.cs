// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Represents a provider of <see cref="Jwk"/>.</summary>
    public interface IKeyProvider
    {
        /// <summary>Gets a list of <see cref="Jwk"/>.</summary>
        Jwk[] GetKeys(JwtHeaderDocument header);

        /// <summary>Force the next call to <see cref="GetKeys(JwtHeaderDocument)"/>
        /// to be refreshed when not successful.</summary>
        void ForceRefresh();

        /// <summary>Gets the issuer of the <see cref="Jwk"/>s.</summary>
        public string Issuer { get; }
    }
}
