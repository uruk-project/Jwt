// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Runtime.CompilerServices;
using System.Text;

namespace JsonWebToken
{
    /// <summary>Represents the error of a token validation.</summary>
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

        /// <summary>Gets the status of the validation.</summary>
        public TokenValidationStatus Status { get; }

        /// <summary>Gets the claim that caused the error.</summary>
        public string? ErrorClaim { get; private set; }

        /// <summary>Gets the header parameter that cause the error.</summary>
        public string? ErrorHeader { get; private set; }

        /// <summary>Gets the <see cref="Exception"/> that caused the error.</summary>
        public Exception? Exception { get; private set; }

        /// <summary>Gets the message that caused the error.</summary>
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

        /// <inheritdoc/>
        public override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append("Status: ").AppendLine(Status.ToString());
            if (Exception is not null)
            {
                builder.Append("Exception: ").AppendLine(Exception.ToString());
            }
            else if(Message is not null)
            {
                builder.Append("Message: ").AppendLine(Message);
            }

            if (ErrorHeader is not null)
            {
                builder.Append("Error Header: ").AppendLine(ErrorHeader);
            }

            if (ErrorClaim is not null)
            {
                builder.Append("Error Claim: ").AppendLine(ErrorClaim);
            }

            return builder.ToString();
        }

        /// <summary>The token has no error.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError NoError()
        {
            return _noError;
        }

        /// <summary>The token has expired, according to the 'nbf' claim.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError Expired()
            => _expired;

        /// <summary>The token was already validated previously.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError TokenReplayed()
            => _tokenReplayed;

        /// <summary>The 'crit' header defines an unsupported header.</summary>
        /// <param name="criticalHeader"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError CriticalHeaderUnsupported(string criticalHeader)
            => new TokenValidationError(TokenValidationStatus.CriticalHeaderUnsupported)
            {
                ErrorHeader = criticalHeader
            };

        /// <summary>The encryption key was not found.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError EncryptionKeyNotFound()
            => _encryptionKeyNotFound;

        /// <summary>The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError MalformedToken()
            => _malformedToken;

        /// <summary>The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.</summary>
        /// <param name="exception"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError MalformedToken(Exception exception)
            => new TokenValidationError(TokenValidationStatus.MalformedToken, exception);

        /// <summary>The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.</summary>
        /// <param name="message"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError MalformedToken(string message)
            => new TokenValidationError(TokenValidationStatus.MalformedToken, message);

        /// <summary>The 'enc' header parameter is missing.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError MissingEncryptionAlgorithm()
            => _missingEncryptionAlgorithm;

        /// <summary>The token is not yet valid, according to the 'nbf' claim.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError NotYetValid()
            => _notYetValid;

        /// <summary>The token decryption has failed.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError DecryptionFailed()
            => _decryptionFailed;

        /// <summary>The token has an invalid claim.</summary>
        /// <param name="claim"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError InvalidClaim(string claim)
            => new TokenValidationError(TokenValidationStatus.InvalidClaim)
            {
                ErrorClaim = claim
            };

        /// <summary>The token has a missing claim.</summary>
        /// <param name="claim"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError MissingClaim(string claim)
            => new TokenValidationError(TokenValidationStatus.MissingClaim)
            {
                ErrorClaim = claim
            };

        /// <summary>The token has an invalid header. </summary>
        /// <param name="header"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError InvalidHeader(string header)
            => new TokenValidationError(TokenValidationStatus.InvalidHeader)
            {
                ErrorHeader = header
            };

        /// <summary>The token has a missing header.</summary>
        /// <param name="header"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError MissingHeader(string header)
            => new TokenValidationError(TokenValidationStatus.MissingHeader)
            {
                ErrorHeader = header
            };

        /// <summary>The token decompression has failed.</summary>
        /// <param name="exception"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationError DecompressionFailed(Exception exception)
            => new TokenValidationError(TokenValidationStatus.DecompressionFailed, exception);

        internal static TokenValidationError SignatureValidationFailed(SignatureValidationError result)
            => new TokenValidationError(result.Status, result.Exception);
    }
}