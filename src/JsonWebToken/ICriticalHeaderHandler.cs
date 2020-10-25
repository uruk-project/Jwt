// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// Represents an extension point for handling the critical header parameter.
    /// </summary>
    public interface ICriticalHeaderHandler
    {
        /// <summary>
        /// Tries to handle a 'crit' header parameter.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="headerName"></param>
        /// <returns></returns>
        bool TryHandle(JwtHeader header, string headerName);
        bool TryHandle(JwtHeaderDocument2 header, string headerName);
        bool TryHandle(JwtHeaderDocument header, string headerName);
    }
}
