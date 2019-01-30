// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Text;
#if NETCOREAPP3_0
using System.Text.Json;
#endif

namespace JsonWebToken
{
    public class PayloadDescriptor : Dictionary<string, JwtProperty>
    {
        public PayloadDescriptor()
        {
        }

        public PayloadDescriptor(JObject json)
        {
            if (json == null)
            {
                throw new ArgumentNullException(nameof(json));
            }

            foreach (var property in json.Properties())
            {
                JwtProperty jwtProperty;
                switch (property.Value.Type)
                {
                    case JTokenType.Object:
                        jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<JObject>());
                        break;
                    case JTokenType.Array:
                        jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<JArray>());
                        break;
                    case JTokenType.Integer:
                        jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<long>());
                        break;
                    case JTokenType.Float:
                        jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<double>());
                        break;
                    case JTokenType.String:
                        jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<string>());
                        break;
                    case JTokenType.Boolean:
                        jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name), property.Value.Value<bool>());
                        break;
                    case JTokenType.Null:
                        jwtProperty = new JwtProperty(Encoding.UTF8.GetBytes(property.Name));
                        break;
                    default:
                        throw new NotSupportedException();
                }

                Add(property.Name, jwtProperty);
            }
        }

        public static explicit operator JObject(PayloadDescriptor payload)
        {
            var o = new JObject();
            foreach (var property in payload.Values)
            {
#if NETSTANDARD
                o.Add(Encoding.UTF8.GetString(property.Utf8Name.ToArray()), new JValue(property.Value));
#else

                o.Add(Encoding.UTF8.GetString(property.Utf8Name.Span), new JValue(property.Value));
#endif
            }

            return o;
        }
    }
}