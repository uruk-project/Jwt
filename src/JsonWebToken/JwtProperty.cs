// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
#if NETCOREAPP3_0
using System.Text.Json;
#endif

namespace JsonWebToken
{
    [JsonConverter(typeof(JwtPropertyConverter))]
    public readonly struct JwtProperty
    {
        private class JwtPropertyConverter : JsonConverter
        {
            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                var o = (JwtProperty)value;

                switch (o.Type)
                {
                    case JwtTokenType.Object:
                        var jObject = JObject.FromObject(o.Value);
                        jObject.WriteTo(writer);
                        break;
                    case JwtTokenType.Array:
                        var jArray = JArray.FromObject(o.Value);
                        jArray.WriteTo(writer);
                        break;
                    case JwtTokenType.Integer:
                        writer.WriteValue((long)o.Value);
                        break;
                    case JwtTokenType.Float:
                        writer.WriteValue((double)o.Value);
                        break;
                    case JwtTokenType.String:
                        writer.WriteValue((string)o.Value);
                        break;
                    case JwtTokenType.Boolean:
                        writer.WriteValue((bool)o.Value);
                        break;
                    case JwtTokenType.Null:
                        writer.WriteNull();
                        break;
                    default:
                        break;
                }
            }

            public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
            {
                throw new NotImplementedException();
            }

            public override bool CanRead
            {
                get { return false; }
            }

            public override bool CanConvert(Type objectType)
            {
                return objectType == typeof(JwtProperty);
            }
        }

        public readonly JwtTokenType Type;

        public readonly ReadOnlyMemory<byte> Utf8Name;

        public readonly object Value;

        //public JwtProperty(JwtTokenType type, ReadOnlyMemory<byte> utf8Name, object value)
        //{
        //    Type = type;
        //    Utf8Name = utf8Name;
        //    Value = value ?? throw new ArgumentNullException(nameof(value));
        //}

        public JwtProperty(ReadOnlyMemory<byte> utf8Name, IReadOnlyList<string> value)
        {
            Type = JwtTokenType.Array;
            Utf8Name = utf8Name;
            Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public JwtProperty(ReadOnlyMemory<byte> utf8Name, JArray value)
        {
            Type = JwtTokenType.Array;
            Utf8Name = utf8Name;
            Value = value ?? throw new ArgumentNullException(nameof(value));
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
    }
}