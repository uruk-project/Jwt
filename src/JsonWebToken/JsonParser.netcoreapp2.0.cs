// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if !NETCOREAPP3_0
using JsonWebToken.Internal;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;

namespace JsonWebToken
{
    public static partial class JsonParser
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static Dictionary<string, object> ReadJson(ReadOnlySpan<byte> buffer)
        {
#if !NETSTANDARD2_0
            var json = Encoding.UTF8.GetString(buffer);
#else
            var json = Encoding.UTF8.GetString(buffer.ToArray());
#endif
            using (JsonTextReader reader = new JsonTextReader(new StringReader(json)))
            {
                return ReadJson(reader);
            }
            //return JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
        }

        internal static Dictionary<string, object> ReadJson(JsonTextReader reader)
        {
            Stack<Dictionary<string, object>> stack = new Stack<Dictionary<string, object>>();
            stack.Push(new Dictionary<string, object>());
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonToken.EndObject:
                        if (stack.Count != 1)
                        {
                            stack.Pop();
                            break;
                        }
                        else
                        {
                            return stack.Peek();
                        }
                    case JsonToken.PropertyName:
                        string name = (string)reader.Value;
                        reader.Read();
                        var type = reader.TokenType;
                        var current = stack.Peek();
                        switch (type)
                        {
                            case JsonToken.String:
                                current[name] = (string)reader.Value;
                                break;
                            case JsonToken.StartObject:
                                var newObj = new Dictionary<string, object>(2);
                                current[name] = newObj;
                                stack.Push(newObj);
                                break;
                            case JsonToken.Boolean:
                                current[name] = (bool)reader.Value;
                                break;
                            case JsonToken.Null:
                                current[name] = null;
                                break;
                            case JsonToken.Integer:
                                current[name] = (long)reader.Value;
                                break;
                            case JsonToken.Float:
                                current[name] = (double)reader.Value;
                                break;
                            case JsonToken.StartArray:
                                var array = ReadJsonArray(reader);
                                current.Add(name, array);
                                break;
                            default:
                                ThrowHelper.FormatMalformedJson();
                                break;
                        }
                        break;
                    case JsonToken.StartObject:
                        break;
                    default:
                        ThrowHelper.FormatMalformedJson();
                        break;
                }
            }

            return stack.Peek();
        }

        internal static List<object> ReadJsonArray(JsonTextReader reader)
        {
            List<object> array = new List<object>(2);
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonToken.EndArray:
                        return array;
                    case JsonToken.Null:
                        array.Add(null);
                        break;
                    case JsonToken.Integer:
                    case JsonToken.Float:
                    case JsonToken.String:
                    case JsonToken.Boolean:
                        array.Add(reader.Value);
                        break;
                    case JsonToken.StartObject:
                        array.Add(ReadJson(reader));
                        break;
                    case JsonToken.StartArray:
                        var innerArray = ReadJsonArray(reader);
                        array.Add(innerArray);
                        break;
                    case JsonToken.EndObject:
                    case JsonToken.PropertyName:
                    default:
                        break;
                }
            }

            return array;
        }
    }
}
#endif
