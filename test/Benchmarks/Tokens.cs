using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace JsonWebToken.Performance
{
    public static class Tokens
    {
        public static readonly IDictionary<string, string> ValidTokens = new Dictionary<string, string>();
        public static readonly IDictionary<string, JObject> Payloads = new Dictionary<string, JObject>();

        static Tokens()
        {
            var location = new Uri(typeof(Tokens).GetTypeInfo().Assembly.CodeBase).AbsolutePath;
            var dirPath = Path.GetDirectoryName(location);
            var tokenPath = Path.Combine(dirPath, "./resources/tokens.json");
            var validTokens = JObject.Load(new JsonTextReader(new StreamReader(tokenPath)));

            foreach (var property in validTokens.Properties())
            {
                ValidTokens.Add(property.Name, property.Value.Value<string>());
            }

            var payloadPath = Path.Combine(dirPath, "./resources/payloads.json");
            var payloads = JObject.Load(new JsonTextReader(new StreamReader(payloadPath)));

            foreach (var property in payloads.Properties())
            {
                Payloads.Add(property.Name, (JObject)property.Value);
            }
        }
    }
}
