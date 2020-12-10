// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace JsonWebToken
{
    /// <summary>Provides options for controling JSON serialization behavior.</summary>
    public static class JsonSerializationBehavior
    {
        private static JavaScriptEncoder _jsonEncoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;

        /// <summary>Gets or sets the <see cref="JsonSerializerOptions"/>.</summary>
        public static JsonSerializerOptions SerializerOptions { get; set; } = CreateDefaultSerializerOptions();

        /// <summary>Gets or sets the <see cref="JavaScriptEncoder"/> used for JSON encoding.</summary>
        /// <remarks>The default value is <see cref="JavaScriptEncoder.UnsafeRelaxedJsonEscaping"/>.</remarks>
        public static JavaScriptEncoder JsonEncoder
        {
            get => _jsonEncoder;
            set
            {
                _jsonEncoder = value;
                NoJsonValidation = new JsonWriterOptions
                {
                    Encoder = value,
                    SkipValidation = true
                };
            }
        }

        internal static JsonWriterOptions NoJsonValidation = new JsonWriterOptions
        {
            Encoder = JsonEncoder,
            SkipValidation = true
        };

        private static JsonSerializerOptions CreateDefaultSerializerOptions()
        {
            var options = new JsonSerializerOptions
            {
                PropertyNamingPolicy = new JsonSnakeCaseNamingPolicy()
            };
            options.Converters.Add(new JsonObjectConverter());

            return options;
        }

        private class JsonObjectConverter : JsonConverter<JsonObject>
        {
            public override void Write(Utf8JsonWriter writer, JsonObject value, JsonSerializerOptions options)
            {
                value.WriteTo(writer);
            }

#if NET5_0
            public override JsonObject? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                throw new NotImplementedException();
            }
#else
            public override JsonObject Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                throw new NotImplementedException();
            }
#endif
        }
    }
}
