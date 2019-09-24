// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Contains a collection of <see cref="Jwk"/>.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public sealed class Jwks : IDisposable
    {
        private Jwk[]? _unidentifiedKeys;
        private Dictionary<string, Jwk[]>? _identifiedKeys;

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
            : this(new[] { key })
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="Jwks"/>.
        /// </summary>
        public Jwks(IList<Jwk> keys)
        {
            if (keys is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.keys);
            }

            for (int i = 0; i < keys!.Count; i++) // ! => [DoesNotReturn]
            {
                var key = keys[i];
                if (key != null)
                {
                    Keys.Add(key);
                }
            }
        }

        /// <summary>
        /// Gets the <see cref="IList{Jwk}"/>.
        /// </summary>       
        public IList<Jwk> Keys { get; } = new List<Jwk>();

        /// <summary>
        /// Gets or sets the first <see cref="Jwk"/> with its 'kid'.
        /// </summary>
        public Jwk? this[string kid]
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
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            Keys.Add(key!); // ! => [DoesNotReturn]
        }

        /// <summary>
        /// Removes the <paramref name="key"/> from the JWKS.
        /// </summary>
        /// <param name="key"></param>
        public void Remove(Jwk key)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            Keys.Remove(key!); // ! => [DoesNotReturn]
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            using (var bufferWriter = new PooledByteBufferWriter())
            {
                using (Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
                {
                    WriteTo(writer);
                }

                var input = bufferWriter.WrittenSpan;
#if NETSTANDARD2_0 || NET461
                return Encoding.UTF8.GetString(input.ToArray());
#else
                return Encoding.UTF8.GetString(input);
#endif
            }
        }

        internal void WriteTo(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            writer.WriteStartObject(JwksParameterNames.KeysUtf8);
            for (int i = 0; i < Keys.Count; i++)
            {
                Keys[i].WriteTo(writer);
            }

            writer.WriteEndObject();
        }

        private string DebuggerDisplay()
        {
            using (var bufferWriter = new PooledByteBufferWriter())
            {
                using (Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
                {
                    WriteTo(writer);
                }

                var input = bufferWriter.WrittenSpan;
#if NETSTANDARD2_0 || NET461
                return Encoding.UTF8.GetString(input.ToArray());
#else
                return Encoding.UTF8.GetString(input);
#endif
            }
        }

        private Jwk[] UnidentifiedKeys
        {
            get
            {
                if (_unidentifiedKeys is null)
                {
                    _unidentifiedKeys = Keys
                                        .Where(jwk => jwk.Kid is null)
                                        .ToArray();
                }

                return _unidentifiedKeys;
            }
        }

        private Dictionary<string, Jwk[]> IdentifiedKeys
        {
            get
            {
                if (_identifiedKeys is null)
                {
                    _identifiedKeys = Keys
                                        .Where(jwk => !(jwk.Kid is null))
                                        .GroupBy(k => k.Kid!)
                                        .ToDictionary(k => k.Key, k => k.Concat(UnidentifiedKeys).ToArray());
                }

                return _identifiedKeys;
            }
        }

        /// <summary>
        /// Gets the list of <see cref="Jwk"/> identified by the 'kid'.
        /// </summary>
        /// <param name="kid"></param>
        /// <returns></returns>
        public Jwk[] GetKeys(string? kid)
        {
            if (kid is null)
            {
                return Keys.ToArray();
            }

            if (IdentifiedKeys.TryGetValue(kid, out var jwks))
            {
                return jwks.ToArray();
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
            if (json is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.json);
            }

            return FromJson(Encoding.UTF8.GetBytes(json!)); // ! => [DoesNotReturn]
        }

        /// <summary>
        /// Returns a new instance of <see cref="Jwks"/>.
        /// </summary>
        /// <param name="json">a string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="Jwks"/></returns>
        public static Jwks FromJson(ReadOnlySpan<byte> json)
        {
            // a JWKS is :
            // {
            //   "keys": [
            //   { jwk1 },
            //   { jwk2 },
            //   ...
            //   ]
            // }
            var jwks = new Jwks();
            var reader = new Utf8JsonReader(json, true, default);

            if (reader.Read()
                && reader.TokenType is JsonTokenType.StartObject
                && reader.Read()
                && reader.TokenType is JsonTokenType.PropertyName)
            {
                var propertyName = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                if (propertyName.Length == 4)
                {
                    ref byte propertyNameRef = ref MemoryMarshal.GetReference(propertyName);
                    if (Unsafe.ReadUnaligned<uint>(ref propertyNameRef) == 1937335659u /* keys */)
                    {
                        if (reader.Read() && reader.TokenType is JsonTokenType.StartArray)
                        {
                            while (reader.Read() && reader.TokenType is JsonTokenType.StartObject)
                            {
                                Jwk jwk = Jwk.FromJsonReader(ref reader);
                                jwks.Add(jwk);
                            }

                            if (!(reader.TokenType is JsonTokenType.EndArray) || !reader.Read())
                            {
                                ThrowHelper.ThrowInvalidOperationException_MalformedJwks();
                            }
                        }
                    }
                }
            }

            if (!(reader.TokenType is JsonTokenType.EndObject))
            {
                ThrowHelper.ThrowInvalidOperationException_MalformedJwks();
            }

            return jwks;
        }

        /// <inheritsdoc />
        public void Dispose()
        {
            IList<Jwk> keys = Keys;
            for (int i = 0; i < keys.Count; i++)
            {
                keys[i].Dispose();
            }
        }
    }
}
