//// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
//// Licensed under the MIT license. See LICENSE in the project root for license information.

//using System.Collections.Generic;
//using System.Diagnostics.CodeAnalysis;

//namespace JsonWebToken.Internal
//{
//    /// <summary>
//    /// Represents a <see cref="IValidator"/> verifying the JWT has a required claim.
//    /// </summary>
//    /// <typeparam name="TClaim"></typeparam>
//    internal sealed class RequiredClaimListValidator<TClaim> : IValidator
//    {
//        private readonly string _claim;
//        private readonly IList<TClaim> _values;

//        /// <summary>
//        /// Initializes an instance of <see cref="RequiredClaimListValidator{TClaim}"/>.
//        /// </summary>
//        /// <param name="claim"></param>
//        /// <param name="values"></param>
//        public RequiredClaimListValidator(string claim, IList<TClaim> values)
//        {
//            if (claim is null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.claim);
//            }

//            if (values is null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.values);
//            }

//            for (int i = 0; i < values.Count; i++)
//            {
//                if (values[i] is null)
//                {
//                    ThrowHelper.ThrowArgumentException_MustNotContainNull(ExceptionArgument.values);
//                }
//            }

//            _claim = claim;
//            _values = values;
//        }

//        /// <inheritdoc />
//        public TokenValidationResult TryValidate(Jwt jwt)
//        {
//            if (jwt is null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.jwt);
//            }

//            if (jwt.Payload is null)
//            {
//                return TokenValidationResult.MalformedToken();
//            }

//            var claim = jwt.Payload[_claim];
//            if (claim is null)
//            {
//                return TokenValidationResult.MissingClaim(jwt, _claim);
//            }

//            for (int i = 0; i < _values.Count; i++)
//            {
//                if (_values[i]!.Equals((TClaim)claim))
//                {
//                    return TokenValidationResult.Success(jwt);
//                }
//            }

//            return TokenValidationResult.InvalidClaim(jwt, _claim);
//        }

//        public bool TryValidate(JwtHeader header, JwtPayload payload, [NotNullWhen(false)] out TokenValidationError? error)
//        {
//            if (payload is null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.payload);
//            }

//            if (payload is null)
//            {
//                error = TokenValidationError.MalformedToken();
//                return false;
//            }

//            var claim = payload[_claim];
//            if (claim is null)
//            {
//                error = TokenValidationError.MissingClaim(_claim);
//                return false;
//            }

//            for (int i = 0; i < _values.Count; i++)
//            {
//                if (_values[i]!.Equals((TClaim)claim))
//                {
//                    error = null;
//                    return true;
//                }
//            }

//            error = TokenValidationError.InvalidClaim(_claim);
//            return false;
//        }

//        public bool TryValidate(JwtHeader header, JwtPayloadDocument payload, [NotNullWhen(false)] out TokenValidationError? error)
//        {
//            if (payload is null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.payload);
//            }

//            if (payload is null)
//            {
//                error = TokenValidationError.MalformedToken();
//                return false;
//            }

//            if (!payload.TryGetValue(_claim, out var claim))
//            {
//                error = TokenValidationError.MissingClaim(_claim);
//                return false;
//            }

//            if (typeof(TClaim) == typeof(string))
//            {
//                var value = claim.GetString();
//                for (int i = 0; i < _values.Count; i++)
//                {
//                    var x = _values[i];
//                    if (!string.Equals((string)x, value, System.StringComparison.OrdinalIgnoreCase))
//                    {
//                        error = null;
//                        return true;
//                    }
//                }

//            }


//            for (int i = 0; i < _values.Count; i++)
//            {
//                if (_values[i]!.Equals((TClaim)claim))
//                {
//                    error = null;
//                    return true;
//                }
//            }

//            error = TokenValidationError.InvalidClaim(_claim);
//            return false;
//        }
//    }
//}
