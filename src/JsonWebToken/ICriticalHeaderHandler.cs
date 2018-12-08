// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

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
        /// <param name="context"></param>
        /// <param name="headerName"></param>
        /// <returns></returns>
        bool TryHandle(CriticalHeaderValidationContext context, string headerName);
    }
}
