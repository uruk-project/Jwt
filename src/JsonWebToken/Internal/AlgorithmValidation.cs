// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken
{
    internal sealed class AlgorithmValidation : IValidator
    {
        private readonly byte[] _algorithm;

        public AlgorithmValidation(string algorithm)
        {
            _algorithm = Utf8.GetBytes(algorithm ?? throw new ArgumentNullException(nameof(algorithm)));
        }

        public bool TryValidate(JwtHeaderDocument header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            if (header is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.header);
            }

            if (header.Alg.IsEmpty)
            {
                error = TokenValidationError.MissingHeader(JwtHeaderParameterNames.Alg.ToString());
                return false;
            }

            if (!header.Alg.ValueEquals(_algorithm))
            {
                error = TokenValidationError.InvalidHeader(JwtHeaderParameterNames.Alg.ToString());
                return false;
            }

            error = null;
            return true;
        }
    }
}
