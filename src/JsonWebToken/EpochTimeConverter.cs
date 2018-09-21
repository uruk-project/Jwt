using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace JsonWebToken
{
    public class EpochTimeConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(DateTime?) || objectType == typeof(long?);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.Null)
            {
                return null;
            }

            if (reader.TokenType == JsonToken.Integer)
            {
                return EpochTime.ToDateTime((long)reader.Value);
            }

            Errors.ThrowUnexpectedTokenParsingDate(reader.TokenType);
            return null;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var epochTime = value as DateTime?;
            if (epochTime.HasValue)
            {
                writer.WriteValue(epochTime.ToEpochTime());
            }
        }
    }
}