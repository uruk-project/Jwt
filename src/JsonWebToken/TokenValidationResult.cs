// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the result of a token validation.
    /// </summary>
    [Obsolete("This class is obsolete. Use the class TokenValidationError instead.")]
    public sealed class TokenValidationResult
    {
        private static readonly TokenValidationResult _success = new TokenValidationResult
        {
            Status = TokenValidationStatus.NoError,
        };
        private static readonly TokenValidationResult _decryptionFailed = new TokenValidationResult
        {
            Status = TokenValidationStatus.DecryptionFailed
        };
        private static readonly TokenValidationResult _malformedToken = new TokenValidationResult
        {
            Status = TokenValidationStatus.MalformedToken
        };
        private static readonly TokenValidationResult _missingEncryptionAlgorithm = new TokenValidationResult
        {
            Status = TokenValidationStatus.MissingEncryptionAlgorithm
        };
        private static readonly TokenValidationResult _encryptionKeyNotFound = new TokenValidationResult
        {
            Status = TokenValidationStatus.EncryptionKeyNotFound
        };

        private TokenValidationResult()
        {
        }

        internal TokenValidationResult(Jwt jwt)
        {
            Token = jwt;
            var error = jwt.Error;
            if (error != null)
            {
                Status = error.Status;
                ErrorClaim = error.ErrorClaim;
                ErrorHeader = error.ErrorHeader;
                Exception = error.Exception;
            }
        }

        /// <summary>
        /// Gets whether the token validation is successful.
        /// </summary>
        public bool Succedeed => Status == TokenValidationStatus.NoError;

        /// <summary>
        /// Gets of set the <see cref="Jwt"/>.
        /// </summary>
        public Jwt? Token { get; private set; }

        /// <summary>
        /// Gets the status of the validation.
        /// </summary>
        public TokenValidationStatus Status { get; private set; }

        /// <summary>
        /// Gets the claim that caused the error.
        /// </summary>
        public string? ErrorClaim { get; private set; }

        /// <summary>
        /// Gets the header parameter that cause the error.
        /// </summary>
        public string? ErrorHeader { get; private set; }

        /// <summary>
        /// Gets the <see cref="Exception"/> that caused the error.
        /// </summary>
        public Exception? Exception { get; private set; }

        /// <summary>
        /// The token has expired, according to the 'nbf' claim.
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult Expired(Jwt token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.Expired,
                Token = token
            };
        }

        /// <summary>
        /// The token was already validated previously.
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult TokenReplayed(Jwt token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.TokenReplayed,
                Token = token
            };
        }

        /// <summary>
        /// The 'crit' header defines an unsupported header.
        /// </summary>
        /// <param name="criticalHeader"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult CriticalHeaderUnsupported(string criticalHeader)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.CriticalHeaderUnsupported,
                ErrorHeader = criticalHeader
            };
        }

        /// <summary>
        /// The encryption key was not found.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult EncryptionKeyNotFound()
        {
            return _encryptionKeyNotFound;
        }

        /// <summary>
        /// The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult MalformedToken()
        {
            return _malformedToken;
        }

        /// <summary>
        /// The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.
        /// </summary>
        /// <param name="exception"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult MalformedToken(Exception exception)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MalformedToken,
                Exception = exception
            };
        }

        /// <summary>
        /// The 'enc' header parameter is missing.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult MissingEncryptionAlgorithm()
        {
            return _missingEncryptionAlgorithm;
        }

        /// <summary>
        /// The token is not yet valid, according to the 'nbf' claim.
        /// </summary>
        /// <param name="jwtToken"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult NotYetValid(Jwt jwtToken)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.NotYetValid,
                Token = jwtToken
            };
        }

        /// <summary>
        /// The token is valid.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult Success()
        {
            return _success;
        }

        /// <summary>
        /// The token is valid.
        /// </summary>
        /// <param name="jwtToken"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult Success(Jwt jwtToken)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.NoError,
                Token = jwtToken
            };
        }

        /// <summary>
        /// The token decryption has failed.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult DecryptionFailed()
        {
            return _decryptionFailed;
        }

        /// <summary>
        /// The token has an invalid claim.
        /// </summary>
        /// <param name="jwt"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult InvalidClaim(Jwt jwt, ReadOnlySpan<byte> claim)
        {
            return new TokenValidationResult
            {
                Token = jwt,
                Status = TokenValidationStatus.InvalidClaim,
                ErrorClaim = Utf8.GetString(claim)
            };
        }

        /// <summary>
        /// The token has an invalid claim.
        /// </summary>
        /// <param name="jwt"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult InvalidClaim(Jwt jwt, string claim)
        {
            return new TokenValidationResult
            {
                Token = jwt,
                Status = TokenValidationStatus.InvalidClaim,
                ErrorClaim = claim
            };
        }

        /// <summary>
        /// The token has a missing claim.
        /// </summary>
        /// <param name="jwt"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult MissingClaim(Jwt jwt, ReadOnlySpan<byte> claim)
        {
            return new TokenValidationResult
            {
                Token = jwt,
                Status = TokenValidationStatus.MissingClaim,
                ErrorClaim = Utf8.GetString(claim)
            };
        }

        /// <summary>
        /// The token has a missing claim.
        /// </summary>
        /// <param name="jwt"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult MissingClaim(Jwt jwt, string claim)
        {
            return new TokenValidationResult
            {
                Token = jwt,
                Status = TokenValidationStatus.MissingClaim,
                ErrorClaim = claim
            };
        }

        /// <summary>
        /// The token has an invalid header. 
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult InvalidHeader(ReadOnlySpan<byte> header)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.InvalidHeader,
                ErrorHeader = Utf8.GetString(header)
            };
        }

        /// <summary>
        /// The token has an invalid header. 
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult InvalidHeader(string header)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.InvalidHeader,
                ErrorHeader = header
            };
        }

        /// <summary>
        /// The token has a missing header.
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult MissingHeader(ReadOnlySpan<byte> header)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingHeader,
                ErrorHeader = Utf8.GetString(header)
            };
        }

        /// <summary>
        /// The token decompression has failed.
        /// </summary>
        /// <param name="exception"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult DecompressionFailed(Exception exception)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.DecompressionFailed,
                Exception = exception
            };
        }

        internal static TokenValidationResult SignatureValidationFailed(SignatureValidationResult result)
        {
            return new TokenValidationResult
            {
                Status = result.Status,
                Exception = result.Exception
            };
        }
    }

    /// <summary>
    /// Represents the error of a token validation.
    /// </summary>
    public sealed class TokenValidationError
    {
        private static readonly TokenValidationError _noError = new TokenValidationError(TokenValidationStatus.NoError);
        private static readonly TokenValidationError _decryptionFailed = new TokenValidationError(TokenValidationStatus.DecryptionFailed);
        private static readonly TokenValidationError _malformedToken = new TokenValidationError(TokenValidationStatus.MalformedToken);
        private static readonly TokenValidationError _missingEncryptionAlgorithm = new TokenValidationError(TokenValidationStatus.MissingEncryptionAlgorithm);
        private static readonly TokenValidationError _encryptionKeyNotFound = new TokenValidationError(TokenValidationStatus.EncryptionKeyNotFound);
        private static readonly TokenValidationError _expired = new TokenValidationError(TokenValidationStatus.Expired);
        private static readonly TokenValidationError _notYetValid = new TokenValidationError(TokenValidationStatus.NotYetValid);
        private static readonly TokenValidationError _tokenReplayed = new TokenValidationError(TokenValidationStatus.TokenReplayed);

        private readonly string? _message;
        /// <summary>
        /// Gets the status of the validation.
        /// </summary>
        public TokenValidationStatus Status { get; }

        /// <summary>
        /// Gets the claim that caused the error.
        /// </summary>
        public string? ErrorClaim { get; private set; }

        /// <summary>
        /// Gets the header parameter that cause the error.
        /// </summary>
        public string? ErrorHeader { get; private set; }

        /// <summary>
        /// Gets the <see cref="Exception"/> that caused the error.
        /// </summary>
        public Exception? Exception { get; private set; }

        /// <summary>
        /// Gets the message that caused the error.
        /// </summary>
        public string? Message => _message;

        private TokenValidationError(TokenValidationStatus status)
        {
            Status = status;
        }

        private TokenValidationError(TokenValidationStatus status, Exception? exception)
        {
            Status = status;
            Exception = exception;
            _message = exception?.Message;
        }

        private TokenValidationError(TokenValidationStatus status, string message)
        {
            Status = status;
            _message = message;
        }

        /// <summary>
        /// The token has no error.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError NoError()
        {
            return _noError;
        }

        /// <summary>
        /// The token has expired, according to the 'nbf' claim.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError Expired()
        {
            return _expired;
        }

        /// <summary>
        /// The token was already validated previously.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError TokenReplayed()
        {
            return _tokenReplayed;
        }

        /// <summary>
        /// The 'crit' header defines an unsupported header.
        /// </summary>
        /// <param name="criticalHeader"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError CriticalHeaderUnsupported(string criticalHeader)
        {
            return new TokenValidationError(TokenValidationStatus.CriticalHeaderUnsupported)
            {
                ErrorHeader = criticalHeader
            };
        }

        /// <summary>
        /// The encryption key was not found.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError EncryptionKeyNotFound()
        {
            return _encryptionKeyNotFound;
        }

        /// <summary>
        /// The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError MalformedToken()
        {
            return _malformedToken;
        }

        /// <summary>
        /// The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.
        /// </summary>
        /// <param name="exception"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError MalformedToken(Exception exception)
        {
            return new TokenValidationError(TokenValidationStatus.MalformedToken, exception);
        }


        /// <summary>
        /// The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError MalformedToken(string message)
        {
            return new TokenValidationError(TokenValidationStatus.MalformedToken, message);
        }

        /// <summary>
        /// The 'enc' header parameter is missing.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError MissingEncryptionAlgorithm()
        {
            return _missingEncryptionAlgorithm;
        }

        /// <summary>
        /// The token is not yet valid, according to the 'nbf' claim.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError NotYetValid()
        {
            return _notYetValid;
        }

        /// <summary>
        /// The token decryption has failed.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError DecryptionFailed()
        {
            return _decryptionFailed;
        }

        /// <summary>
        /// The token has an invalid claim.
        /// </summary>
        /// <param name="claim"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError InvalidClaim(ReadOnlySpan<byte> claim)
        {
            return new TokenValidationError(TokenValidationStatus.InvalidClaim)
            {
                ErrorClaim = Utf8.GetString(claim)
            };
        }

        /// <summary>
        /// The token has an invalid claim.
        /// </summary>
        /// <param name="claim"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError InvalidClaim(string claim)
        {
            return new TokenValidationError(TokenValidationStatus.InvalidClaim)
            {
                ErrorClaim = claim
            };
        }

        /// <summary>
        /// The token has a missing claim.
        /// </summary>
        /// <param name="claim"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError MissingClaim(ReadOnlySpan<byte> claim)
        {
            return new TokenValidationError(TokenValidationStatus.MissingClaim)
            {
                ErrorClaim = Utf8.GetString(claim)
            };
        }

        /// <summary>
        /// The token has a missing claim.
        /// </summary>
        /// <param name="claim"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError MissingClaim(string claim)
        {
            return new TokenValidationError(TokenValidationStatus.MissingClaim)
            {
                ErrorClaim = claim
            };
        }

        /// <summary>
        /// The token has an invalid header. 
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError InvalidHeader(ReadOnlySpan<byte> header)
        {
            return new TokenValidationError(TokenValidationStatus.InvalidHeader)
            {
                ErrorHeader = Utf8.GetString(header)
            };
        }

        /// <summary>
        /// The token has an invalid header. 
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError InvalidHeader(string header)
        {
            return new TokenValidationError(TokenValidationStatus.InvalidHeader)
            {
                ErrorHeader = header
            };
        }

        /// <summary>
        /// The token has a missing header.
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError MissingHeader(ReadOnlySpan<byte> header)
        {
            return new TokenValidationError(TokenValidationStatus.MissingHeader)
            {
                ErrorHeader = Utf8.GetString(header)
            };
        }

        /// <summary>
        /// The token decompression has failed.
        /// </summary>
        /// <param name="exception"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError DecompressionFailed(Exception exception)
        {
            return new TokenValidationError(TokenValidationStatus.DecompressionFailed, exception);
        }

        internal static TokenValidationError SignatureValidationFailed(SignatureValidationResult result)
        {
            return new TokenValidationError(result.Status, result.Exception);
        }
    }
}