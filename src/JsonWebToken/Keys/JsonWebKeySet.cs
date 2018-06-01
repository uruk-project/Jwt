using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Contains a collection of <see cref="JsonWebKey"/> that can be populated from a json string.
    /// </summary>
    /// <remarks>provides support for http://tools.ietf.org/html/rfc7517.</remarks>
    [JsonObject]
    public class JsonWebKeySet
    {
        /// <summary>
        /// Returns a new instance of <see cref="JsonWebKeySet"/>.
        /// </summary>
        /// <param name="json">a string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="JsonWebKeySet"/></returns>
        public static JsonWebKeySet Create(string json)
        {
            if (string.IsNullOrEmpty(json))
            {
                throw new ArgumentNullException(nameof(json));
            }

            return new JsonWebKeySet(json);
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeySet"/>.
        /// </summary>
        public JsonWebKeySet()
        {
        }

        public JsonWebKeySet(JsonWebKey key)
            : this(new[] { key ?? throw new ArgumentNullException(nameof(key)) })
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeySet"/>.
        /// </summary>
        public JsonWebKeySet(IEnumerable<JsonWebKey> keys)
        {
            Keys = new List<JsonWebKey>(keys);
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeySet"/> from a json string.
        /// </summary>
        /// <param name="json">a json string containing values.</param>
        public JsonWebKeySet(string json)
        {
            if (string.IsNullOrEmpty(json))
            {
                throw new ArgumentNullException(nameof(json));
            }

            JsonConvert.PopulateObject(json, this);
        }

        /// <summary>
        /// When deserializing from JSON any properties that are not defined will be placed here.
        /// </summary>
        [JsonExtensionData]
        public IDictionary<string, object> AdditionalData { get; } = new Dictionary<string, object>();

        /// <summary>
        /// Gets the <see cref="IList{JsonWebKey}"/>.
        /// </summary>       
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeySetParameterNames.Keys, Required = Required.Default, ItemConverterType = typeof(JsonWebKey.JwkJsonConverter))]
        public IList<JsonWebKey> Keys { get; } = new List<JsonWebKey>();

        public JsonWebKey this[string kid]
        {
            get
            {
                for (int i = 0; i < Keys.Count; i++)
                {
                    if (string.Equals(kid, Keys[i].Kid, StringComparison.Ordinal))
                    {
                        return Keys[i];
                    }
                }

                return null;
            }
        }

        public void Add(JsonWebKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            Keys.Add(key);
        }

        public void Remove(JsonWebKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            Keys.Remove(key);
        }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }
    }
}
