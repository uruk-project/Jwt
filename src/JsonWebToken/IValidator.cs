// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// Represents a validation to apply to a <see cref="TokenValidationContext"/>.
    /// </summary>
    public interface IValidator
    {
        /// <summary>
        /// Tries to validate a token.
        /// </summary>
        TokenValidationResult TryValidate(Jwt jwt);
    }
}
