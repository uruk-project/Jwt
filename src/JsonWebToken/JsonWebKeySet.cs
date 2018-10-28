// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;

namespace JsonWebToken
{
    /// <summary>
    /// Contains a collection of <see cref="JsonWebKey"/>.
    /// </summary>
    [JsonObject]
    public class JsonWebKeySet
    {
        public static readonly JsonWebKeySet Empty = new JsonWebKeySet();
        private JsonWebKey[] _unidentifiedKeys;
        private Dictionary<string, List<JsonWebKey>> _identifiedKeys;

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
        public JsonWebKeySet(ICollection<JsonWebKey> keys)
        {
            if (keys == null)
            {
                throw new ArgumentNullException(nameof(keys));
            }

            var k = new JsonWebKey[keys.Count];
            keys.CopyTo(k, 0);
            Keys = new List<JsonWebKey>(k);
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

        /// <summary>
        /// Gets or sets the first <see cref="JsonWebKey"/> with its 'kid'.
        /// </summary>
        public JsonWebKey this[string kid]
        {
            get
            {
                for (int i = 0; i < Keys.Count; i++)
                {
                    var key = Keys[i];
                    if (string.Equals(kid, key.Kid, StringComparison.Ordinal))
                    {
                        return key;
                    }
                }

                return null;
            }
        }

        /// <summary>
        /// Returns a new instance of <see cref="JsonWebKeySet"/>.
        /// </summary>
        /// <param name="json">a string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="JsonWebKeySet"/></returns>
        public static JsonWebKeySet FromJson(string json)
        {
            if (string.IsNullOrEmpty(json))
            {
                throw new ArgumentNullException(nameof(json));
            }

            return new JsonWebKeySet(json);
        }

        /// <summary>
        /// Adds the <paramref name="key"/> to the JWKS.
        /// </summary>
        /// <param name="key"></param>
        public void Add(JsonWebKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            Keys.Add(key);
        }

        /// <summary>
        /// Removes the <paramref name="key"/> from the JWKS.
        /// </summary>
        /// <param name="key"></param>
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

        private IReadOnlyList<JsonWebKey> UnidentifiedKeys
        {
            get
            {
                if (_unidentifiedKeys == null)
                {
                    _unidentifiedKeys = Keys
                                        .Where(jwk => jwk.Kid == null)
                                        .ToArray();
                }

                return _unidentifiedKeys;
            }
        }

        private IDictionary<string, List<JsonWebKey>> IdentifiedKeys
        {
            get
            {
                if (_identifiedKeys == null)
                {
                    _identifiedKeys = Keys
                                        .Where(jwk => jwk.Kid != null)
                                        .GroupBy(k => k.Kid)
                                        .ToDictionary(k => k.Key, k => k.Concat(UnidentifiedKeys).ToList());
                }

                return _identifiedKeys;
            }
        }

        /// <summary>
        /// Gets the list of <see cref="JsonWebKey"/> identified by the 'kid'.
        /// </summary>
        /// <param name="kid"></param>
        /// <returns></returns>
        public IReadOnlyList<JsonWebKey> GetKeys(string kid)
        {
            if (kid == null)
            {
                return Keys.ToArray();
            }

            if (IdentifiedKeys.TryGetValue(kid, out var jwks))
            {
                return jwks;
            }

            return UnidentifiedKeys;
        }

        public static implicit operator JsonWebKeySet(JsonWebKey[] keys) => new JsonWebKeySet(keys);
    }
}
