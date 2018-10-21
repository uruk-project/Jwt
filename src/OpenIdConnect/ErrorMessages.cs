// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    internal static class ErrorMessages
    {
        public static string VotIncorrectLength()
        {
            return "Invalid vector value. The length is incorrect.";
        }

        public static string VotIncorrectDimension(char dimension)
        {
            return $"Invalid vector value. The dimension '{dimension}' is not valid.";
        }

        public static string VotIncorrectValue(char value, char dimension)
        {
            return $"Invalid vector value. The value '{value}' for dimension '{dimension}' is not valid. Must be a lowercase letter [a-z] or a single digit [0-9].";
        }

        public static string VotIncorrectSeparator(char separator)
        {
            return $"Invalid vector value. The separator '{separator}' is not valid. Should be '.'.";
        }

        public static string VotTooManyValues(char dimension, char value)
        {
            return $"Invalid vector value. The dimension '{dimension}' define the value '{value}' more than once.";
        }
    }
}
