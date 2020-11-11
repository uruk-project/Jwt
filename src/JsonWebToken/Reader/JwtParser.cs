// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

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
        ///// <summary>
        ///// Use the <paramref name="reader"/> as JSON input and returns a <see cref="JwtObject"/>.
        ///// </summary>
        ///// <param name="reader"></param>
        //public static JwtObject ReadJsonObject(ref Utf8JsonReader reader)
        //{
        //    var current = new JwtObject();
        //    while (reader.Read() && reader.TokenType is JsonTokenType.PropertyName)
        //    {
        //        var name = reader.ValueSpan /* reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan */;
        //        reader.Read();
        //        var type = reader.TokenType;
        //        switch (type)
        //        {
        //            case JsonTokenType.StartObject:
        //                current.Add(name, ReadJsonObject(ref reader));
        //                break;
        //            case JsonTokenType.StartArray:
        //                current.Add(name, ReadJsonArray(ref reader));
        //                break;
        //            case JsonTokenType.String:
        //                current.Add(name, reader.GetString()!);
        //                break;
        //            case JsonTokenType.True:
        //                current.Add(name, true);
        //                break;
        //            case JsonTokenType.False:
        //                current.Add(name, false);
        //                break;
        //            case JsonTokenType.Null:
        //                current.Add(name);
        //                break;
        //            case JsonTokenType.Number:
        //                if (reader.TryGetInt64(out long longValue))
        //                {
        //                    current.Add(name, longValue);
        //                }
        //                else
        //                {
        //                    current.Add(name, reader.GetDouble());
        //                }
        //                break;
        //            default:
        //                ThrowHelper.ThrowFormatException_MalformedJson();
        //                break;
        //        }
        //    }

        //    if (!(reader.TokenType is JsonTokenType.EndObject))
        //    {
        //        ThrowHelper.ThrowFormatException_MalformedJson();
        //    }

        //    return current;
        //}

        ///// <summary>
        ///// Use the <paramref name="reader"/> as JSON input and returns a <see cref="JwtArray"/>.
        ///// </summary>
        ///// <param name="reader"></param>
        //public static JwtArray ReadJsonArray(ref Utf8JsonReader reader)
        //{
        //    var array = new JwtArray(new List<JwtValue>(2));
        //    while (reader.Read())
        //    {
        //        switch (reader.TokenType)
        //        {
        //            case JsonTokenType.EndArray:
        //                return array;

        //            case JsonTokenType.StartObject:
        //                array.Add(ReadJsonObject(ref reader));
        //                break;
        //            case JsonTokenType.StartArray:
        //                var innerArray = ReadJsonArray(ref reader);
        //                array.Add(innerArray);
        //                break;
        //            case JsonTokenType.Null:
        //                array.Add(JwtValue.Null);
        //                break;
        //            case JsonTokenType.Number:
        //                if (reader.TryGetInt64(out long longValue))
        //                {
        //                    array.Add(longValue);
        //                }
        //                else
        //                {
        //                    array.Add(reader.GetDouble());
        //                }

        //                break;
        //            case JsonTokenType.String:
        //                string valueString = reader.GetString()!;
        //                array.Add(valueString);
        //                break;
        //            case JsonTokenType.True:
        //                array.Add(JwtValue.True);
        //                break;
        //            case JsonTokenType.False:
        //                array.Add(JwtValue.False);
        //                break;
        //            case JsonTokenType.EndObject:
        //            case JsonTokenType.PropertyName:
        //            default:
        //                break;
        //        }
        //    }

        //    // If we are here, we are missing a closing brace.
        //    ThrowHelper.ThrowFormatException_MalformedJson();
        //    return default;
        //}

        ///// <summary>
        ///// Use the <paramref name="reader"/> as JSON input and returns a <see cref="JwtArray"/>.
        ///// </summary>
        ///// <param name="reader"></param>
        //public static string[] ReadStringArray(ref Utf8JsonReader reader)
        //{
        //    var array = new List<string>(2);
        //    while (reader.Read() && reader.TokenType == JsonTokenType.String)
        //    {
        //        array.Add(reader.GetString()!);
        //    }

        //    if (reader.TokenType != JsonTokenType.EndArray)
        //    {
        //        ThrowHelper.ThrowFormatException_MalformedJson($"Expected an array of string. A value of type {reader.TokenType} was found.");
        //    }

        //    return array.ToArray();
        //}

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
            ThrowHelper.ThrowFormatException_MalformedJson();
        }
    }
}
