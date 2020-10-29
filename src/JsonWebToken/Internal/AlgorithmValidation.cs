// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken.Internal
{
    internal sealed class AlgorithmValidation : IValidator
    {
        private readonly byte[] _algorithm;

        public AlgorithmValidation(string algorithm)
        {
            _algorithm = Utf8.GetBytes(algorithm ?? throw new ArgumentNullException(nameof(algorithm)));
        }

        [Obsolete("This method is obsolete. Use TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, out TokenValidationError? error) instead.")]
        public TokenValidationResult TryValidate(Jwt jwt)
        {
            if (jwt is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.jwt);
            }

            if (!jwt.Header.TryGetHeaderParameter(HeaderParameters.AlgUtf8, out var property))
            {
                return TokenValidationResult.MissingHeader(HeaderParameters.AlgUtf8);
            }

            if (!new ReadOnlyMemory<byte>(_algorithm).Equals(property.GetRawValue()))
            {
                return TokenValidationResult.InvalidHeader(HeaderParameters.AlgUtf8);
            }

            return TokenValidationResult.Success(jwt);
        }

        public bool TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (header is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.header);
            }

            if (!header.TryGetHeaderParameter(HeaderParameters.AlgUtf8, out var property))
            {
                error = TokenValidationError.MissingHeader(HeaderParameters.AlgUtf8);
                return false;
            }

            if (!property.ValueEquals(_algorithm))
            {
                error = TokenValidationError.InvalidHeader(HeaderParameters.AlgUtf8);
                return false;
            }

            error = null;
            return true;
        }
    }
}
