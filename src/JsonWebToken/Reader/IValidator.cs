﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken
{
    /// <summary>Represents a validation to apply to a <see cref="Jwt"/>.</summary>
    public interface IValidator
    {
        /// <summary>Tries to validate a token.</summary>
        bool TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error);
    }
}
