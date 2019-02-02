//// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
//// Licensed under the MIT license. See the LICENSE file in the project root for more information.

//using JsonWebToken.Internal;
//using Newtonsoft.Json;
//using Newtonsoft.Json.Linq;
//using System;
//using System.Collections.Generic;
//using System.Text;
//#if NETCOREAPP3_0
//using System.Text.Json;
//#endif

//namespace JsonWebToken
//{
//#if !NETCOREAPP3_0
//    public class HeaderDescriptorConverter : JsonConverter
//    {
//        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
//        {
//            var header = (DescriptorDictionary)value;
//            writer.WriteStartObject();
//            for (int i = 0; i < header.Count; i++)
//            {
//                var property = header[i];
//#if NETSTANDARD2_0
//                writer.WritePropertyName(EncodingHelper.GetUtf8String(property.Utf8Name.Span));
//#else
//                writer.WritePropertyName(Encoding.UTF8.GetString(property.Utf8Name.Span));
//#endif
//                switch (property.Type)
//                {
//                    case JwtTokenType.Object:
//                        var jObject = (JObject)property.Value;
//                        jObject.WriteTo(writer);
//                        break;
//                    case JwtTokenType.Array:
//                        var jArray = (JArray)property.Value;
//                        jArray.WriteTo(writer);
//                        break;
//                    case JwtTokenType.Integer:
//                        writer.WriteValue((long)property.Value);
//                        break;
//                    case JwtTokenType.Float:
//                        writer.WriteValue((double)property.Value);
//                        break;
//                    case JwtTokenType.String:
//                        writer.WriteValue((string)property.Value);
//                        break;
//                    case JwtTokenType.Boolean:
//                        writer.WriteValue((bool)property.Value);
//                        break;
//                    case JwtTokenType.Null:
//                        writer.WriteNull();
//                        break;
//                    default:
//                        break;
//                }
//            }

//            writer.WriteEndObject();
//        }

//        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
//        {
//            throw new NotImplementedException();
//        }

//        public override bool CanRead
//        {
//            get { return false; }
//        }

//        public override bool CanConvert(Type objectType)
//        {
//            return objectType == typeof(DescriptorDictionary);
//        }
//    }

////    public class PayloadDescriptorConverter : JsonConverter
////    {
////        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
////        {
////            var payload = (PayloadDescriptor)value;

////            writer.WriteStartObject();
////            foreach (var property in payload.Values)
////            {
////#if NETSTANDARD2_0
////                writer.WritePropertyName(EncodingHelper.GetUtf8String(property.Utf8Name.Span));
////#else
////                writer.WritePropertyName(Encoding.UTF8.GetString(property.Utf8Name.Span));
////#endif
////                switch (property.Type)
////                {
////                    case JwtTokenType.Object:
////                        var jObject = (JObject)property.Value;
////                        jObject.WriteTo(writer);
////                        break;
////                    case JwtTokenType.Array:
////                        var jArray = (JArray)property.Value;
////                        jArray.WriteTo(writer);
////                        break;
////                    case JwtTokenType.Integer:
////                        writer.WriteValue((long)property.Value);
////                        break;
////                    case JwtTokenType.Float:
////                        writer.WriteValue((double)property.Value);
////                        break;
////                    case JwtTokenType.String:
////                        writer.WriteValue((string)property.Value);
////                        break;
////                    case JwtTokenType.Boolean:
////                        writer.WriteValue((bool)property.Value);
////                        break;
////                    case JwtTokenType.Null:
////                        writer.WriteNull();
////                        break;
////                    default:
////                        break;
////                }
////            }

////            writer.WriteEndObject();
////        }

////        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
////        {
////            throw new NotImplementedException();
////        }

////        public override bool CanRead
////        {
////            get { return false; }
////        }

////        public override bool CanConvert(Type objectType)
////        {
////            return objectType == typeof(PayloadDescriptor);
////        }
////    }
//#endif

////#if !NETCOREAPP3_0
////    [JsonConverter(typeof(PayloadDescriptorConverter))]
////#endif
////    public class PayloadDescriptor : Dictionary<string, JwtProperty>
////    {
////        public PayloadDescriptor()
////        {
////        }

////        public PayloadDescriptor(JObject json)
////        {
////            if (json == null)
////            {
////                throw new ArgumentNullException(nameof(json));
////            }

////            foreach (var property in json.Properties())
////            {
////                JwtProperty jwtProperty;
////                switch (property.Value.Type)
////                {
////                    case JTokenType.Object:
////                        jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<JObject>());
////                        break;
////                    case JTokenType.Array:
////                        jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<JArray>());
////                        break;
////                    case JTokenType.Integer:
////                        jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<long>());
////                        break;
////                    case JTokenType.Float:
////                        jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<double>());
////                        break;
////                    case JTokenType.String:
////                        jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<string>());
////                        break;
////                    case JTokenType.Boolean:
////                        jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<bool>());
////                        break;
////                    case JTokenType.Null:
////                        jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name));
////                        break;
////                    default:
////                        throw new NotSupportedException();
////                }

////                Add(property.Name, jwtProperty);
////            }
////        }

////        public static explicit operator JObject(PayloadDescriptor payload)
////        {
////            var o = new JObject();
////            foreach (var property in payload.Values)
////            {
////#if NETSTANDARD
////                o.Add(Encoding.UTF8.GetString(property.Utf8Name.ToArray()), new JValue(property.Value));
////#else

////                o.Add(Encoding.UTF8.GetString(property.Utf8Name.Span), new JValue(property.Value));
////#endif
////            }

////            return o;
////        }
////    }
//}