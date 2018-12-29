// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if NETCOREAPP3_0
using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace JsonWebToken
{
    public static partial class JsonParser
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static Dictionary<string, object> ReadJson(ReadOnlySpan<byte> buffer)
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
                        string name = reader.GetStringValue();
                        reader.Read();
                        var type = reader.TokenType;
                        var current = stack.Peek();
                        switch (type)
                        {
                            case JsonTokenType.String:
                                current[name] = reader.GetStringValue();
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
                                if (reader.TryGetInt64Value(out long longValue))
                                {
                                    current[name] = longValue;
                                }
                                else
                                {
                                    if (reader.TryGetDoubleValue(out double doubleValue))
                                    {
                                        current[name] = doubleValue;
                                    }
                                    else
                                    {
                                        ThrowHelper.FormatNotSupportedNumber(name);
                                    }
                                }
                                break;
                            case JsonTokenType.StartArray:
                                var array = ReadJsonArray(ref reader);
                                current.Add(name, array);
                                break;
                            default:
                                ThrowHelper.FormatMalformedJson();
                                break;
                        }
                        break;
                    case JsonTokenType.StartObject:
                        break;
                    default:
                        ThrowHelper.FormatMalformedJson();
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
                        if (reader.TryGetInt64Value(out long longValue))
                        {
                            array.Add(longValue);
                        }
                        else
                        {
                            if (reader.TryGetDoubleValue(out double doubleValue))
                            {
                                array.Add(doubleValue);
                            }
                            else
                            {
                                ThrowHelper.FormatMalformedJson();
                            }
                        }

                        break;
                    case JsonTokenType.String:
                        string valueString = reader.GetStringValue();
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

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        internal static bool ThreeBytesEqual(ref byte first, ref byte second, int length)
        {
            if (length != 3)
            {
                goto NotEqual;
            }

            if (first != second)
            {
                goto NotEqual;
            }

            if (Unsafe.Add(ref first, 1) != (Unsafe.Add(ref second, 1)))
            {
                goto NotEqual;
            }

            if (Unsafe.Add(ref first, 2) != (Unsafe.Add(ref second, 2)))
            {
                goto NotEqual;
            }

            return true;

            NotEqual: // Workaround for https://github.com/dotnet/coreclr/issues/13549
            return false;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        internal static bool FourBytesEqual(ref byte first, ref byte second, int length)
        {
            if (length != 4)
            {
                goto NotEqual;
            }

            if (first != second)
            {
                goto NotEqual;
            }

            if (Unsafe.Add(ref first, 1) != (Unsafe.Add(ref second, 1)))
            {
                goto NotEqual;
            }

            if (Unsafe.Add(ref first, 2) != (Unsafe.Add(ref second, 2)))
            {
                goto NotEqual;
            }

            if (Unsafe.Add(ref first, 3) != (Unsafe.Add(ref second, 3)))
            {
                goto NotEqual;
            }

            return true;

            NotEqual: // Workaround for https://github.com/dotnet/coreclr/issues/13549
            return false;
        }
    }
}
#endif