using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class AudienceConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return objectType.IsAssignableFrom(typeof(ICollection<string>));
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.Null)
            {
                return null;
            }

            if (reader.TokenType == JsonToken.String)
            {
                return new string[] { (string)reader.Value };
            }

            if (reader.TokenType == JsonToken.StartArray)
            {
                var audiences = new List<string>();
                reader.Read();
                while (reader.TokenType == JsonToken.String)
                {
                    var audience = reader.ReadAsString();
                    audiences.Add(audience);
                }

                return audiences;
            }

            throw new JsonSerializationException("The 'aud' property is invalid. Expected string or array of string.");
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            if (value is IList<string> list && list.Count != 0)
            {
                if (list.Count == 1)
                {
                    writer.WriteValue(list[0]);
                }
                else
                {
                    writer.WriteStartArray();
                    for (int i = 0; i < list.Count; i++)
                    {
                        writer.WriteValue(list[i]);
                    }
                }

                writer.WriteEndArray();
            }
        }
    }
}
