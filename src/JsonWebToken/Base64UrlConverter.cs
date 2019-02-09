// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json;
using System;
using System.Text;

namespace JsonWebToken
{
    internal sealed class Base64UrlConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return true;
            //return typeof(Jwk).GetTypeInfo().IsAssignableFrom(objectType.GetTypeInfo());
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            return Base64Url.Base64UrlDecode((string)reader.Value);
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            writer.WriteValue(Encoding.UTF8.GetString(Base64Url.Base64UrlEncode((byte[])value)));
        }
    }
}