// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Provides methods for converting Base64Url JSON data into a <see cref="Dictionary{TKey, TValue}"/>
    /// </summary>
    public static partial class JsonParser
    {
        /// <summary>
        /// Parses the UTF-8 <paramref name="buffer"/> as JSON and returns a <see cref="Dictionary{TKey, TValue}"/>.
        /// </summary>
        /// <param name="buffer"></param>
        public static JwtObject Parse(ReadOnlySpan<byte> buffer)
        {
            Utf8JsonReader reader = new Utf8JsonReader(buffer, true, default);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                JwtThrowHelper.FormatMalformedJson();
            }

            return ReadJsonObject(ref reader);
        }

        internal static JwtObject ReadJwtHeader(ref Utf8JsonReader reader)
        {
            // TODO :specialize this reader for Header
            return ReadJsonObject(ref reader);
        }

        internal static JwtObject ReadJwtPayload(ref Utf8JsonReader reader)
        {
            // TODO :specialize this reader for Payload
            return ReadJsonObject(ref reader);
        }

        internal static JwtObject ReadJsonObject(ref Utf8JsonReader reader)
        {
            var current = new JwtObject();
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndObject:
                        return current;
                    case JsonTokenType.PropertyName:
                        var name = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                        reader.Read();
                        var type = reader.TokenType;
                        switch (type)
                        {
                            case JsonTokenType.String:
                                current.Add(new JwtProperty(name, reader.GetString()));
                                break;
                            case JsonTokenType.StartObject:
                                current.Add(new JwtProperty(name, ReadJsonObject(ref reader)));
                                break;
                            case JsonTokenType.True:
                                current.Add(new JwtProperty(name, true));
                                break;
                            case JsonTokenType.False:
                                current.Add(new JwtProperty(name, false));
                                break;
                            case JsonTokenType.Null:
                                current.Add(new JwtProperty(name));
                                break;
                            case JsonTokenType.Number:
                                if (reader.TryGetInt64(out long longValue))
                                {
                                    current.Add(new JwtProperty(name, longValue));
                                }
                                else
                                {
                                    if (reader.TryGetDouble(out double doubleValue))
                                    {
                                        current.Add(new JwtProperty(name, doubleValue));
                                    }
                                    else
                                    {
                                        JwtThrowHelper.FormatNotSupportedNumber(name);
                                    }
                                }
                                break;
                            case JsonTokenType.StartArray:
                                var array = ReadJsonArray(ref reader);
                                current.Add(new JwtProperty(name, array));
                                break;
                            default:
                                JwtThrowHelper.FormatMalformedJson();
                                break;
                        }
                        break;
                    default:
                        JwtThrowHelper.FormatMalformedJson();
                        break;
                }
            }

            JwtThrowHelper.FormatMalformedJson();
            return null;
        }

        internal static JwtArray ReadJsonArray(ref Utf8JsonReader reader)
        {
            List<JwtValue> array = new List<JwtValue>(2);
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndArray:
                        return new JwtArray(array);
                    case JsonTokenType.Null:
                        array.Add(JwtValue.Null);
                        break;
                    case JsonTokenType.Number:
                        if (reader.TryGetInt64(out long longValue))
                        {
                            array.Add(new JwtValue(longValue));
                        }
                        else
                        {
                            if (reader.TryGetDouble(out double doubleValue))
                            {
                                array.Add(new JwtValue(doubleValue));
                            }
                            else
                            {
                                JwtThrowHelper.FormatMalformedJson();
                            }
                        }

                        break;
                    case JsonTokenType.String:
                        string valueString = reader.GetString();
                        array.Add(new JwtValue(valueString));
                        break;
                    case JsonTokenType.True:
                        array.Add(JwtValue.True);
                        break;
                    case JsonTokenType.False:
                        array.Add(JwtValue.False);
                        break;
                    case JsonTokenType.StartObject:
                        array.Add(new JwtValue(ReadJsonObject(ref reader)));
                        break;
                    case JsonTokenType.StartArray:
                        var innerArray = ReadJsonArray(ref reader);
                        array.Add(new JwtValue(innerArray));
                        break;
                    case JsonTokenType.EndObject:
                    case JsonTokenType.PropertyName:
                    default:
                        break;
                }
            }

            // If we are here, we are missing a closing brace.
            JwtThrowHelper.FormatMalformedJson();
            return default;
        }

        internal static void ConsumeJsonObject(ref Utf8JsonReader reader)
        {
            int objectCount = 0;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndObject:
                        if (objectCount != 1)
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
            JwtThrowHelper.FormatMalformedJson();
        }

        /// <summary>
        /// Consume a JSON array.
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
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
            JwtThrowHelper.FormatMalformedJson();
        }
    }
}
