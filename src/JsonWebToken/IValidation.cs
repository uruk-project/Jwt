// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    /// <summary>
    /// Represents a validation to apply to a <see cref="TokenValidationContext"/>.
    /// </summary>
    public interface IValidation
    {
        TokenValidationResult TryValidate(in TokenValidationContext context);
    }
}
