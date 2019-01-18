// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Globalization;
#if NETCOREAPP3_0
using System.Text.Json;
#else
using Newtonsoft.Json;
#endif

namespace JsonWebToken.Internal
{
    internal static class ThrowHelper
    {
        public static void ThrowArgumentOutOfRangeException()
        {
            throw GetArgumentOutOfRangeException();
        }

        public static void ThrowMalformedInputException(int inputLength)
        {
            throw GetMalformdedInputException(inputLength);
        }

        public static void ThrowOperationNotDone(OperationStatus status)
        {
            throw GetOperationNotDoneException(status);
        }

        public static void NotSupportedKey(string keyType)
        {
            throw new NotSupportedException("The key type '{keyType}' is not supported.");
        }

        public static void NotSupportedKey()
        {
            throw new NotSupportedException("The key is not supported.");
        }

        private static ArgumentOutOfRangeException GetArgumentOutOfRangeException()
        {
            return new ArgumentOutOfRangeException("length");
        }

        private static Exception GetOperationNotDoneException(OperationStatus status)
        {
            switch (status)
            {
                case OperationStatus.DestinationTooSmall:
                    return new InvalidOperationException(DestinationTooSmall);
                case OperationStatus.InvalidData:
                    return new FormatException(InvalidInput);
                default:                                // This case won't happen.
                    throw new NotSupportedException();  // Just in case new states are introduced
            }
        }

        private static FormatException GetMalformdedInputException(int inputLength)
        {
            return new FormatException(FormatMalformedInput(inputLength));
        }

        /// <summary>
        /// Malformed input: {0} is an invalid input length.
        /// </summary>
        internal static readonly string MalformedInput = "Malformed input: {0} is an invalid input length.";

        /// <summary>
        /// Invalid input, that doesn't conform a base64url string.
        /// </summary>
        internal static readonly string InvalidInput = "The input is not a valid Base-64 URL string as it contains a non-base 64 character.";

        /// <summary>
        /// Destination buffer is too small.
        /// </summary>
        internal static readonly string DestinationTooSmall = "The destination buffer is too small.";

        /// <summary>
        /// Malformed input: {0} is an invalid input length.
        /// </summary>
        internal static string FormatMalformedInput(int p0)
        {
            return string.Format(CultureInfo.CurrentCulture, MalformedInput, p0);
        }

#if NETCOREAPP3_0
        /// <summary>
        /// The claim '{claim}' must be of type {type}.
        /// </summary>
        internal static string FormatMalformedJson(string claim, JsonTokenType type)
        {
            throw new FormatException($"The claim '{claim}' must be of type {type}.");
        }
#else
        /// <summary>
        /// The claim '{claim}' must be of type {type}.
        /// </summary>
        internal static string FormatMalformedJson(string claim, JsonToken type)
        {
            throw new FormatException($"The claim '{claim}' must be of type {type}.");
        }
#endif

        /// <summary>
        /// The claim '{name}' is not a supported Number value.
        /// </summary>
        internal static string FormatNotSupportedNumber(string name)
        {
            throw new FormatException($"The claim '{name}' is not a supported Number value.");
        }

        /// <summary>
        /// The JSON is malformed.
        /// </summary>
        internal static string FormatMalformedJson()
        {
            throw new FormatException("The JSON is malformed.");
        }

        /// <summary>
        /// Expect a JSON object.
        /// </summary>
        internal static string FormatNotJson()
        {
            throw new FormatException("Expect a JSON object.");
        }
//#endif
    }
}