// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Represents a static provider of keys.</summary>
    public sealed class StaticKeyProvider : IKeyProvider
    {
        private readonly Jwks _jwks;

        /// <summary>Initializes a new instance of <see cref="StaticKeyProvider"/>.</summary>
        public StaticKeyProvider(Jwks jwks)
        {
            if (jwks is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.jwks);
            }

            _jwks = jwks;
        }

        /// <inheritdoc/>
        public string Issuer => _jwks.Issuer;

        /// <inheritdoc/>
        public void ForceRefresh()
        {
            // static JWKS refreshment is a no-op.
        }

        /// <summary>Gets the list of <see cref="Jwk"/>.</summary>
        public Jwk[] GetKeys(JwtHeaderDocument header)
        {
            return _jwks.GetKeys(header.Kid);
        }
    }
}
