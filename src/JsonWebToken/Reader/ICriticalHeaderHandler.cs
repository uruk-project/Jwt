// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Represents an extension point for handling the critical header parameter.</summary>
    public interface ICriticalHeaderHandler
    {
        /// <summary>Tries to handle a 'crit' header parameter.</summary>
        bool TryHandle(JwtHeaderDocument header, string headerName);
    }
}
