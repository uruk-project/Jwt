// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Represent a standard JWT payload.
    /// </summary>
    public interface IJwtPayloadDescriptor
    {
        /// <summary>
        /// Gets or sets the subject 'sub'.
        /// </summary>
        string Subject { get; set; }
        
        /// <summary>
        /// Gets or sets the audiences 'aud'.
        /// </summary>
        IReadOnlyList<string> Audiences { get; set; }

        /// <summary>
        /// Gets or sets the expiration time 'exp'.
        /// </summary>
        DateTime? ExpirationTime { get; set; }

        /// <summary>
        /// Gets or sets the issued time 'iat'.
        /// </summary>
        DateTime? IssuedAt { get; set; }

        /// <summary>
        /// Gets or sets the issuer 'iss'.
        /// </summary>
        string Issuer { get; set; }

        /// <summary>
        /// Gets or set the JWT identifier 'jti'.
        /// </summary>
        string JwtId { get; set; }

        /// <summary>
        /// Gets or sets the "not before" time 'nbf'.
        /// </summary>
        DateTime? NotBefore { get; set; }
    }
}