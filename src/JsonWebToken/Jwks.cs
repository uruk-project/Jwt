// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Contains a collection of <see cref="Jwk"/>.
    /// </summary>
    public sealed class Jwks
    {
        private Jwk[] _unidentifiedKeys;
        private Dictionary<string, List<Jwk>> _identifiedKeys;

        /// <summary>
        /// Initializes an new instance of <see cref="Jwks"/>.
        /// </summary>
        public Jwks()
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="Jwks"/>.
        /// </summary>
        /// <param name="key"></param>
        public Jwks(Jwk key)
            : this(new[] { key ?? throw new ArgumentNullException(nameof(key)) })
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="Jwks"/>.
        /// </summary>
        public Jwks(ICollection<Jwk> keys)
        {
            if (keys == null)
            {
                throw new ArgumentNullException(nameof(keys));
            }

            var k = new Jwk[keys.Count];
            keys.CopyTo(k, 0);
            Keys = new List<Jwk>(k);
        }

        /// <summary>
        /// Gets the <see cref="IList{Jwk}"/>.
        /// </summary>       
        public IList<Jwk> Keys { get; } = new List<Jwk>();

        /// <summary>
        /// Gets or sets the first <see cref="Jwk"/> with its 'kid'.
        /// </summary>
        public Jwk this[string kid]
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
        /// Adds the <paramref name="key"/> to the JWKS.
        /// </summary>
        /// <param name="key"></param>
        public void Add(Jwk key)
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
        public void Remove(Jwk key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            Keys.Remove(key);
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            using (var bufferWriter = new ArrayBufferWriter<byte>())
            {
                Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterState(new JsonWriterOptions { Indented = true }));
                WriteTo(ref writer);
                writer.Flush();

                var input = bufferWriter.WrittenSpan;
                return Encoding.UTF8.GetString(input.ToArray());
            }
        }

        internal void WriteTo(ref Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            writer.WriteStartObject(JwksParameterNames.KeysUtf8);
            for (int i = 0; i < Keys.Count; i++)
            {
                Keys[i].WriteTo(ref writer);
            }

            writer.WriteEndObject();
        }

        private string DebuggerDisplay()
        {
            using (var bufferWriter = new ArrayBufferWriter<byte>())
            {
                Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterState(new JsonWriterOptions { Indented = true }));

                WriteTo(ref writer);
                writer.Flush();

                var input = bufferWriter.WrittenSpan;
                return Encoding.UTF8.GetString(input.ToArray());
            }
        }

        private IReadOnlyList<Jwk> UnidentifiedKeys
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

        private Dictionary<string, List<Jwk>> IdentifiedKeys
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
        /// Gets the list of <see cref="Jwk"/> identified by the 'kid'.
        /// </summary>
        /// <param name="kid"></param>
        /// <returns></returns>
        public IReadOnlyList<Jwk> GetKeys(string kid)
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

        /// <summary>
        /// Cast the array of <see cref="Jwk"/> into a <see cref="Jwks"/>.
        /// </summary>
        /// <param name="keys"></param>
        public static implicit operator Jwks(Jwk[] keys) => new Jwks(keys);

        /// <summary>
        /// Returns a new instance of <see cref="Jwks"/>.
        /// </summary>
        /// <param name="json">a string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="Jwks"/></returns>
        public static Jwks FromJson(string json)
        {
            if (json == null)
            {
                throw new ArgumentNullException(nameof(json));
            }

            return FromJson(Encoding.UTF8.GetBytes(json));
        }

        /// <summary>
        /// Returns a new instance of <see cref="Jwks"/>.
        /// </summary>
        /// <param name="json">a string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="Jwks"/></returns>
        public unsafe static Jwks FromJson(ReadOnlySpan<byte> json)
        {
            // a JWKS is :
            // {
            //   "keys": [
            //   { jwk1 },
            //   { jwk2 },
            //   ???
            //   ]
            // }
            var jwks = new Jwks();
            var reader = new Utf8JsonReader(json, true, default);

            reader.Read();
            if (reader.TokenType == JsonTokenType.StartObject && reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var propertyName = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                if (propertyName.Length == 4)
                {
                    fixed (byte* pPropertyName = propertyName)
                    {
                        if (*((uint*)pPropertyName) == 1937335659u /* keys */)
                        {
                            reader.Read();
                            if (reader.TokenType == JsonTokenType.StartArray)
                            {
                                while (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
                                {
                                    Jwk jwk = Jwk.FromJsonReader(ref reader);
                                    jwks.Add(jwk);
                                }

                                if (reader.Read() && reader.TokenType == JsonTokenType.EndObject)
                                {
                                    return jwks;
                                }
                            }
                        }
                    }
                }
            }

            Errors.ThrowMalformedJwks();
            return null;
        }
    }
}
