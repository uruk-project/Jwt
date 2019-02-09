// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

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
            return ReadJson(ref reader);
        }

        internal static JwtObject ReadJson(ref Utf8JsonReader reader)
        {
            Stack<JwtObject> stack = new Stack<JwtObject>(2);
            stack.Push(new JwtObject());
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndObject:
                        if (stack.Count != 1)
                        {
                            stack.Pop();
                            break;
                        }
                        else
                        {
                            return stack.Peek();
                        }
                    case JsonTokenType.PropertyName:
                        byte[] name = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray();
                        reader.Read();
                        var type = reader.TokenType;
                        var current = stack.Peek();
                        switch (type)
                        {
                            case JsonTokenType.String:
                                current.Add(new JwtProperty(name, reader.GetString()));
                                break;
                            case JsonTokenType.StartObject:
                                var jwtObject = new JwtObject();
                                current.Add(new JwtProperty(name, jwtObject));
                                stack.Push(jwtObject);
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
                                        JwtThrowHelper.FormatNotSupportedNumber(Encoding.UTF8.GetString(name));
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
                    case JsonTokenType.StartObject:
                        break;
                    default:
                        JwtThrowHelper.FormatMalformedJson();
                        break;
                }
            }

            return stack.Peek();
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
                        array.Add(new JwtValue(ReadJson(ref reader)));
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
    }
}
