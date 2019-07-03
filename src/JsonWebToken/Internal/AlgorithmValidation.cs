// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Text;

namespace JsonWebToken.Internal
{
    internal sealed class AlgorithmValidation : IValidator
    {
        private readonly byte[] _algorithm;

        public AlgorithmValidation(string algorithm)
        {
            _algorithm = Encoding.UTF8.GetBytes(algorithm ?? throw new ArgumentNullException(nameof(algorithm)));
        }

        public TokenValidationResult TryValidate(in TokenValidationContext context)
        {
            var jwt = context.Jwt;
            if (!jwt.Header.TryGetValue(HeaderParameters.AlgUtf8, out var property))
            {
                return TokenValidationResult.MissingHeader(HeaderParameters.AlgUtf8);
            }

            if (!_algorithm.AsSpan().SequenceEqual((byte[])property.Value))
            {
                return TokenValidationResult.InvalidHeader(HeaderParameters.AlgUtf8);
            }

            return TokenValidationResult.Success(jwt);
        }
    }
}
