// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    internal static class Utf8JsonReaderHelper
    {
        public static int SkipArray(ref Utf8JsonReader reader)
        {
            int count = 0;
            int depth = reader.CurrentDepth;
            int depth2 = depth + 1;
            do
            {
                var tokenType = reader.TokenType;
                if (depth2 == reader.CurrentDepth && (tokenType == JsonTokenType.StartArray || tokenType == JsonTokenType.StartObject || tokenType >= JsonTokenType.String))
                {
                    count++;
                }
            }
            while (reader.Read() && depth < reader.CurrentDepth);
            return count;
        }

        public static int SkipObject(ref Utf8JsonReader reader)
        {
            int count = 0;
            int depth = reader.CurrentDepth;
            if (reader.Read())
            {
                int depth2 = depth + 1;
                do
                {
                    if (depth2 == reader.CurrentDepth && reader.TokenType == JsonTokenType.PropertyName)
                    {
                        count++;
                    }
                }
                while (depth < reader.CurrentDepth && reader.Read());
            }

            return count;
        }
    }
}