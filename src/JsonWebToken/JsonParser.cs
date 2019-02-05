// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
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
        public static Dictionary<string, object> Parse(ReadOnlySpan<byte> buffer)
        {
            Utf8JsonReader reader = new Utf8JsonReader(buffer, true, default);
            return ReadJson(ref reader);
        }

        internal static Dictionary<string, object> ReadJson(ref Utf8JsonReader reader)
        {
            Stack<Dictionary<string, object>> stack = new Stack<Dictionary<string, object>>();
            stack.Push(new Dictionary<string, object>());
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
                        string name = reader.GetString();
                        reader.Read();
                        var type = reader.TokenType;
                        var current = stack.Peek();
                        switch (type)
                        {
                            case JsonTokenType.String:
                                current[name] = reader.GetString();
                                break;
                            case JsonTokenType.StartObject:
                                var newObj = new Dictionary<string, object>(2);
                                current[name] = newObj;
                                stack.Push(newObj);
                                break;
                            case JsonTokenType.True:
                                current[name] = true;
                                break;
                            case JsonTokenType.False:
                                current[name] = false;
                                break;
                            case JsonTokenType.Null:
                                current[name] = null;
                                break;
                            case JsonTokenType.Number:
                                if (reader.TryGetInt64(out long longValue))
                                {
                                    current[name] = longValue;
                                }
                                else
                                {
                                    if (reader.TryGetDouble(out double doubleValue))
                                    {
                                        current[name] = doubleValue;
                                    }
                                    else
                                    {
                                        JwtThrowHelper.FormatNotSupportedNumber(name);
                                    }
                                }
                                break;
                            case JsonTokenType.StartArray:
                                var array = ReadJsonArray(ref reader);
                                current.Add(name, array);
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

        internal static List<object> ReadJsonArray(ref Utf8JsonReader reader)
        {
            List<object> array = new List<object>(2);
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndArray:
                        return array;
                    case JsonTokenType.Null:
                        array.Add(null);
                        break;
                    case JsonTokenType.Number:
                        if (reader.TryGetInt64(out long longValue))
                        {
                            array.Add(longValue);
                        }
                        else
                        {
                            if (reader.TryGetDouble(out double doubleValue))
                            {
                                array.Add(doubleValue);
                            }
                            else
                            {
                                JwtThrowHelper.FormatMalformedJson();
                            }
                        }

                        break;
                    case JsonTokenType.String:
                        string valueString = reader.GetString();
                        array.Add(valueString);
                        break;
                    case JsonTokenType.True:
                        array.Add(true);
                        break;
                    case JsonTokenType.False:
                        array.Add(false);
                        break;
                    case JsonTokenType.StartObject:
                        array.Add(ReadJson(ref reader));
                        break;
                    case JsonTokenType.StartArray:
                        var innerArray = ReadJsonArray(ref reader);
                        array.Add(innerArray);
                        break;
                    case JsonTokenType.EndObject:
                    case JsonTokenType.PropertyName:
                    default:
                        break;
                }
            }

            return array;
        }
    }
}
