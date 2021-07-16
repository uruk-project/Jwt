// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>Represents an exception occuring while checking the validity of a JWK.</summary>
    public class JwkValidationException : Exception
    {
        /// <summary>Initializes a new instance of the <see cref="JwkValidationException"/> class</summary>
        public JwkValidationException(string? message)
            : base(message)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="JwkValidationException"/> class</summary>
        public JwkValidationException(string? message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }
}
