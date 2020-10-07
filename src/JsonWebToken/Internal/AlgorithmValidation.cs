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

        public TokenValidationResult TryValidate(Jwt jwt)
        {
            if (jwt is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.jwt);
            }

            if (!jwt.Header.TryGetValue(HeaderParameters.AlgUtf8, out var property))
            {
                return TokenValidationResult.MissingHeader(HeaderParameters.AlgUtf8);
            }

            if (!_algorithm.AsSpan().SequenceEqual(new ReadOnlySpan<byte>((byte[]?)property.Value)))
            {
                return TokenValidationResult.InvalidHeader(HeaderParameters.AlgUtf8);
            }

            return TokenValidationResult.Success(jwt);
        }

        public bool TryValidate(JwtHeader header, JwtPayload payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (header is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.header);
            }

            if (!header.TryGetValue(HeaderParameters.AlgUtf8, out var property))
            {
                error = TokenValidationError.MissingHeader(HeaderParameters.AlgUtf8);
                return false;
            }

            if (!_algorithm.AsSpan().SequenceEqual(new ReadOnlySpan<byte>((byte[]?)property.Value)))
            {
                error = TokenValidationError.InvalidHeader(HeaderParameters.AlgUtf8);
                return false;
            }

            error = null;
            return true;
        }
    }
}
