// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Collections.Generic;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Provides methods for parsing JSON data into a <see cref="Dictionary{TKey, TValue}"/></summary>
    public static partial class JsonParser
    {
        internal static void ConsumeJsonObject(ref Utf8JsonReader reader)
        {
            int objectCount = 0;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndObject:
                        if (objectCount != 0)
                        {
                            objectCount--;
                            break;
                        }
                        else
                        {
                            return;
                        }
                    case JsonTokenType.PropertyName:
                        reader.Read();
                        var type = reader.TokenType;
                        switch (type)
                        {
                            case JsonTokenType.StartObject:
                                ConsumeJsonObject(ref reader);
                                objectCount++;
                                break;
                            case JsonTokenType.StartArray:
                                ConsumeJsonArray(ref reader);
                                break;
                            default:
                                break;
                        }
                        break;
                    default:
                        break;
                }
            }

            // If we are here, we are missing a closing brace.
            ThrowHelper.ThrowFormatException_MalformedJson();
        }

        /// <summary>Consume a JSON array.</summary>
        /// <param name="reader"></param>
        internal static void ConsumeJsonArray(ref Utf8JsonReader reader)
        {
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndArray:
                        return;
                    case JsonTokenType.StartObject:
                        ConsumeJsonObject(ref reader);
                        break;
                    case JsonTokenType.StartArray:
                        ConsumeJsonArray(ref reader);
                        break;
                    default:
                        break;
                }
            }

            // If we are here, we are missing a closing bracket.
            ThrowHelper.ThrowFormatException_MalformedJson();
        }
    }
}
