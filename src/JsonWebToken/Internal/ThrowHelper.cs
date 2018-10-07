using System;
using System.Buffers;
using System.Globalization;

namespace JsonWebToken
{
    internal static class ThrowHelper
    {
        public static void ThrowArgumentNullException()
        {
            throw GetArgumentNullException();
        }

        public static void ThrowArgumentOutOfRangeException()
        {
            throw GetArgumentOutOfRangeException();
        }

        public static void ThrowInvalidCountOffsetOrLengthException()
        {
            throw GetInvalidCountOffsetOrLengthException();
        }

        public static void ThrowMalformedInputException(int inputLength)
        {
            throw GetMalformdedInputException(inputLength);
        }

        public static void ThrowOperationNotDone(OperationStatus status)
        {
            throw GetOperationNotDoneException(status);
        }

        public static ArgumentNullException GetArgumentNullException()
        {
            return new ArgumentNullException("length");
        }

        public static ArgumentOutOfRangeException GetArgumentOutOfRangeException()
        {
            return new ArgumentOutOfRangeException("length");
        }

        public static ArgumentException GetInvalidCountOffsetOrLengthException()
        {
            return new ArgumentException(InvalidCountOffsetOrLength, "length");
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
        /// Invalid {0}, {1} or {2} length.
        /// </summary>
        internal static readonly string InvalidCountOffsetOrLength = "Invalid length.";

        /// <summary>
        /// Malformed input: {0} is an invalid input length.
        /// </summary>
        internal static readonly string MalformedInput = "Malformed input: {0} is an invalid input length.";

        /// <summary>
        /// Invalid input, that doesn't conform a base64 string.
        /// </summary>
        internal static readonly string InvalidInput = "The input is not a valid Base-64 string as it contains a non-base 64 character, more than two padding characters, or an illegal character among the padding characters.";

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
    }
}