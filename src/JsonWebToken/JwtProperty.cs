// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Text.Json;
#if NETCOREAPP3_0
using System.Text.Json;
#endif

namespace JsonWebToken
{
    public readonly struct JwtArray
    {
        private readonly List<JwtValue> _inner;

        public JwtArray(List<JwtValue> values)
        {
            _inner = new List<JwtValue>(values);
        }

        public JwtArray(List<string> values)
        {
            var list = new List<JwtValue>(values.Count);
            for (int i = 0; i < values.Count; i++)
            {
                list.Add(new JwtValue(values[i]));
            }

            _inner = list;
        }

        public List<JwtValue> ToList() => _inner;

        public int Count => _inner.Count;

        public JwtValue this[int index] => _inner[index];

        internal void WriteTo(ref Utf8JsonWriter writer)
        {
            writer.WriteStartArray();
            for (int i = 0; i < _inner.Count; i++)
            {
                _inner[i].WriteTo(ref writer);
            }

            writer.WriteEndArray();
        }

        internal void WriteTo(ref Utf8JsonWriter writer, ReadOnlySpan<byte> utf8Name)
        {
            writer.WriteStartArray(utf8Name);
            for (int i = 0; i < _inner.Count; i++)
            {
                _inner[i].WriteTo(ref writer);
            }

            writer.WriteEndArray();
        }
    }

    public readonly struct JwtProperty
    {
        public readonly JwtTokenType Type;

        public readonly ReadOnlyMemory<byte> Utf8Name;

        public readonly object Value;

        public JwtProperty(ReadOnlyMemory<byte> utf8Name, JwtArray value)
        {
            Type = JwtTokenType.Array;
            Utf8Name = utf8Name;
            Value = value;
        }

        public JwtProperty(ReadOnlyMemory<byte> utf8Name, JObject value)
        {
            Type = JwtTokenType.Object;
            Utf8Name = utf8Name;
            Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public JwtProperty(ReadOnlyMemory<byte> utf8Name, string value)
        {
            Type = JwtTokenType.String;
            Utf8Name = utf8Name;
            Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        //public JwtProperty(ReadOnlyMemory<byte> utf8Name, ReadOnlyMemory<byte> value)
        //{
        //    Type = JwtTokenType.String;
        //    Utf8Name = utf8Name;
        //    Value = value;
        //}

        public JwtProperty(ReadOnlyMemory<byte> utf8Name, long value)
        {
            Type = JwtTokenType.Integer;
            Utf8Name = utf8Name;
            Value = value;
        }

        public JwtProperty(ReadOnlyMemory<byte> utf8Name, int value)
        {
            Type = JwtTokenType.Integer;
            Utf8Name = utf8Name;
            Value = value;
        }

        public JwtProperty(ReadOnlyMemory<byte> utf8Name, double value)
        {
            Type = JwtTokenType.Float;
            Utf8Name = utf8Name;
            Value = value;
        }

        public JwtProperty(ReadOnlyMemory<byte> utf8Name, float value)
        {
            Type = JwtTokenType.Float;
            Utf8Name = utf8Name;
            Value = value;
        }

        public JwtProperty(ReadOnlyMemory<byte> utf8Name, bool value)
        {
            Type = JwtTokenType.Boolean;
            Utf8Name = utf8Name;
            Value = value;
        }

        public JwtProperty(ReadOnlyMemory<byte> utf8Name)
        {
            Type = JwtTokenType.Null;
            Utf8Name = utf8Name;
            Value = null;
        }

        internal void WriteTo(ref Utf8JsonWriter writer)
        {
            switch (Type)
            {
                case JwtTokenType.Object:
                    writer.WriteStartObject(Utf8Name.Span);
                    WriteObject(ref writer, (JObject)Value);
                    writer.WriteEndObject();
                    break;
                case JwtTokenType.Array:
                    var array = (JwtArray)Value;
                    array.WriteTo(ref writer, Utf8Name.Span);
                    break;
                case JwtTokenType.Integer:
                    writer.WriteNumber(Utf8Name.Span, (long)Value);
                    break;
                case JwtTokenType.Float:
                    writer.WriteNumber(Utf8Name.Span, (double)Value);
                    break;
                case JwtTokenType.String:
                    writer.WriteString(Utf8Name.Span, (string)Value, false);
                    break;
                case JwtTokenType.Boolean:
                    writer.WriteBoolean(Utf8Name.Span, (bool)Value);
                    break;
                case JwtTokenType.Null:
                    writer.WriteNull(Utf8Name.Span);
                    break;
                default:
                    throw new JsonWriterException($"The type {Type} is not supported.");
            }
        }

        private static void WriteArray(ref Utf8JsonWriter writer, JArray value)
        {
            for (int i = 0; i < value.Count; i++)
            {
                var token = value[i];
                switch (token.Type)
                {
                    case JTokenType.Object:
                        writer.WriteStartObject();
                        WriteObject(ref writer, (JObject)token);
                        writer.WriteEndObject();
                        break;
                    case JTokenType.Array:
                        writer.WriteStartArray();
                        WriteArray(ref writer, (JArray)token);
                        writer.WriteEndArray();
                        break;
                    case JTokenType.Integer:
                        writer.WriteNumberValue((long)token);
                        break;
                    case JTokenType.Float:
                        writer.WriteNumberValue((double)token);
                        break;
                    case JTokenType.String:
                        writer.WriteStringValue((string)token);
                        break;
                    case JTokenType.Boolean:
                        writer.WriteBooleanValue((bool)token);
                        break;
                    case JTokenType.Null:
                        writer.WriteNullValue();
                        break;
                    default:
                        throw new JsonWriterException($"The type {value.Type} is not supported.");
                }
            }
        }

        private static void WriteObject(ref Utf8JsonWriter writer, JObject jObject)
        {
#if NETSTANDARD2_0
            foreach (var kvp in jObject)
            {
                var key = kvp.Key;
                var value = kvp.Value;
#else
            foreach ((var key, var value) in jObject)
            {
#endif
                switch (value.Type)
                {
                    case JTokenType.Object:
                        writer.WriteStartObject(key);
                        WriteObject(ref writer, (JObject)value);
                        writer.WriteEndObject();
                        break;
                    case JTokenType.Array:
                        writer.WriteStartArray(key);
                        WriteArray(ref writer, (JArray)value);
                        writer.WriteEndArray();
                        break;
                    case JTokenType.Integer:
                        writer.WriteNumber(key, (long)value);
                        break;
                    case JTokenType.Float:
                        writer.WriteNumber(key, (double)value);
                        break;
                    case JTokenType.String:
                        writer.WriteString(key, (string)value, false);
                        break;
                    case JTokenType.Boolean:
                        writer.WriteBoolean(key, (bool)value);
                        break;
                    case JTokenType.Null:
                        writer.WriteNull(key);
                        break;
                    default:
                        throw new JsonWriterException($"The type {value.Type} is not supported.");
                }
            }
        }
    }

    public readonly struct JwtValue
    {
        public readonly JwtTokenType Type;

        public readonly object Value;

        public JwtValue(JwtArray value)
        {
            Type = JwtTokenType.Array;
            Value = value;
        }

        public JwtValue(JObject value)
        {
            Type = JwtTokenType.Object;
            Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public JwtValue(string value)
        {
            Type = JwtTokenType.String;
            Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        //public JwtValue(ReadOnlyMemory<byte> utf8Name, ReadOnlyMemory<byte> value)
        //{
        //    Type = JwtTokenType.String;
        //    Value = value;
        //}

        public JwtValue(long value)
        {
            Type = JwtTokenType.Integer;
            Value = value;
        }

        public JwtValue(int value)
        {
            Type = JwtTokenType.Integer;
            Value = value;
        }

        public JwtValue(double value)
        {
            Type = JwtTokenType.Float;
            Value = value;
        }

        public JwtValue(float value)
        {
            Type = JwtTokenType.Float;
            Value = value;
        }

        public JwtValue(bool value)
        {
            Type = JwtTokenType.Boolean;
            Value = value;
        }

        internal void WriteTo(ref Utf8JsonWriter writer)
        {
            switch (Type)
            {
                case JwtTokenType.Object:
                    writer.WriteStartObject();
                    WriteObject(ref writer, (JObject)Value);
                    writer.WriteEndObject();
                    break;
                case JwtTokenType.Array:
                    var array = (JwtArray)Value;
                    array.WriteTo(ref writer);
                    break;
                case JwtTokenType.Integer:
                    writer.WriteNumberValue((long)Value);
                    break;
                case JwtTokenType.Float:
                    writer.WriteNumberValue((double)Value);
                    break;
                case JwtTokenType.String:
                    writer.WriteStringValue((string)Value, false);
                    break;
                case JwtTokenType.Boolean:
                    writer.WriteBooleanValue((bool)Value);
                    break;
                case JwtTokenType.Null:
                    writer.WriteNullValue();
                    break;
                default:
                    throw new JsonWriterException($"The type {Type} is not supported.");
            }
        }

        private static void WriteObject(ref Utf8JsonWriter writer, JObject jObject)
        {
#if NETSTANDARD2_0
            foreach (var kvp in jObject)
            {
                var key = kvp.Key;
                var value = kvp.Value;
#else
            foreach ((var key, var value) in jObject)
            {
#endif
                switch (value.Type)
                {
                    case JTokenType.Object:
                        writer.WriteStartObject(key);
                        WriteObject(ref writer, (JObject)value);
                        writer.WriteEndObject();
                        break;
                    case JTokenType.Array:
                        writer.WriteStartArray(key);
                        WriteArray(ref writer, (JArray)value);
                        writer.WriteEndArray();
                        break;
                    case JTokenType.Integer:
                        writer.WriteNumber(key, (long)value);
                        break;
                    case JTokenType.Float:
                        writer.WriteNumber(key, (double)value);
                        break;
                    case JTokenType.String:
                        writer.WriteString(key, (string)value, false);
                        break;
                    case JTokenType.Boolean:
                        writer.WriteBoolean(key, (bool)value);
                        break;
                    case JTokenType.Null:
                        writer.WriteNull(key);
                        break;
                    default:
                        throw new JsonWriterException($"The type {value.Type} is not supported.");
                }
            }
        }

        private static void WriteArray(ref Utf8JsonWriter writer, JArray value)
        {
            for (int i = 0; i < value.Count; i++)
            {
                var token = value[i];
                switch (token.Type)
                {
                    case JTokenType.Object:
                        writer.WriteStartObject();
                        WriteObject(ref writer, (JObject)token);
                        writer.WriteEndObject();
                        break;
                    case JTokenType.Array:
                        writer.WriteStartArray();
                        WriteArray(ref writer, (JArray)token);
                        writer.WriteEndArray();
                        break;
                    case JTokenType.Integer:
                        writer.WriteNumberValue((long)token);
                        break;
                    case JTokenType.Float:
                        writer.WriteNumberValue((double)token);
                        break;
                    case JTokenType.String:
                        writer.WriteStringValue((string)token);
                        break;
                    case JTokenType.Boolean:
                        writer.WriteBooleanValue((bool)token);
                        break;
                    case JTokenType.Null:
                        writer.WriteNullValue();
                        break;
                    default:
                        throw new JsonWriterException($"The type {value.Type} is not supported.");
                }
            }
        }
    }
}