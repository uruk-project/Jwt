// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    public sealed class Actor 
    {
        private readonly JwtObject _inner;

        public Actor(JwtObject inner)
        {
            _inner = inner;
        }

        public Actor NestedActor => _inner.TryGetValue(OAuth2Claims.ActUtf8, out var property) ? new Actor((JwtObject)property.Value) : null;

        public string Subject { get; set; }

        public static Actor FromJson(string json)
        {
            return FromJson(Encoding.UTF8.GetBytes(json));
        }

        public static Actor FromJson(ReadOnlySpan<byte> json)
        {
            var reader = new Utf8JsonReader(json, true, default);
            return new Actor(JsonParser.ReadJsonObject(ref reader));
        }

        public override string ToString()
        {
            return _inner.ToString();
        }

        public byte[] Serialize()
        {
            using (var bufferWriter = new ArrayBufferWriter<byte>())
            {
                using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { SkipValidation = true }))
                {
                    _inner.WriteTo(writer);
                }

                var input = bufferWriter.WrittenSpan;
                return input.ToArray();
            }
        }
    }
}
