// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    /// <summary>
    /// Represents the validation context for the critical header 'crit'.
    /// </summary>
    public readonly struct CriticalHeaderValidationContext
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CriticalHeaderValidationContext"/> class.
        /// </summary>
        /// <param name="header"></param>
        public CriticalHeaderValidationContext(JwtHeader header)
        {
            Header = header;
        }

        /// <summary>
        /// Gets the header.
        /// </summary>
        public readonly JwtHeader Header;
    }
}
