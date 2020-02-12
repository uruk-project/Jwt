// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Contains a collection of <see cref="Jwk"/>.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public sealed class Jwks : IDisposable
    {
        private const uint keys = 1937335659u;
        private readonly List<Jwk> _keys = new List<Jwk>();

        private Jwk[]? _keyArray;
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
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            _keys.Add(key);
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

            for (int i = 0; i < keys.Count; i++)
            {
                var key = keys[i];
                if (key != null)
                {
                    _keys.Add(key);
                }
            }
        }

        /// <summary>
        /// Gets or sets the first <see cref="Jwk"/> with its 'kid'.
        /// </summary>
        public Jwk? this[string kid]
        {
            get
            {
                var keys = _keys;
                for (int i = 0; i < keys.Count; i++)
                {
                    var key = keys[i];
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

            _identifiedKeys = null;
            _unidentifiedKeys = null;
            _keyArray = null;
            _keys.Add(key);
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

            _identifiedKeys = null;
            _unidentifiedKeys = null;
            _keyArray = null;
            _keys.Remove(key);
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                WriteTo(writer);
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }

        internal void WriteTo(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            writer.WriteStartObject(JwksParameterNames.KeysUtf8);
            var keys = _keys;
            for (int i = 0; i < keys.Count; i++)
            {
                keys[i].WriteTo(writer);
            }

            writer.WriteEndObject();
        }

        private string DebuggerDisplay()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (Utf8JsonWriter writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                WriteTo(writer);
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }

        private Jwk[] UnidentifiedKeys
        {
            get
            {
                if (_unidentifiedKeys is null)
                {
                    _unidentifiedKeys = _keys
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
                    _identifiedKeys = _keys
                                        .Where(jwk => !(jwk.Kid is null))
                                        .GroupBy(k => k.Kid!)
                                        .ToDictionary(k => k.Key, k => k.Concat(UnidentifiedKeys).ToArray());
                }

                return _identifiedKeys;
            }
        }

        /// <summary>
        /// Gets the number of keys contained in the <see cref="Jwks"/>.
        /// </summary>
        public int Count => _keys.Count;

        /// <summary>
        /// Gets the list of <see cref="Jwk"/> identified by the 'kid'.
        /// </summary>
        /// <param name="kid"></param>
        /// <returns></returns>
        public Jwk[] GetKeys(string? kid)
        {
            if (kid is null)
            {
                return _keyArray ?? (_keyArray = _keys.ToArray());
            }

            if (IdentifiedKeys.TryGetValue(kid, out var jwks))
            {
                return jwks;
            }

            return UnidentifiedKeys;
        }

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

            byte[]? jsonToReturn = null;
            try
            {
                int length = Utf8.GetMaxByteCount(json.Length);
                Span<byte> jsonSpan = length <= Constants.MaxStackallocBytes
                            ? stackalloc byte[length]
                            : (jsonToReturn = ArrayPool<byte>.Shared.Rent(length));
                length = Utf8.GetBytes(json, jsonSpan);
                return FromJson(jsonSpan.Slice(0, length));
            }
            finally
            {
                if (jsonToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(jsonToReturn);
                }
            }
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
                var propertyName = reader.ValueSpan /* reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan */;
                if (propertyName.Length == 4)
                {
                    ref byte propertyNameRef = ref MemoryMarshal.GetReference(propertyName);
                    if (IntegerMarshal.ReadUInt32(ref propertyNameRef) == keys /* keys */)
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
            var keys = _keys;
            for (int i = 0; i < keys.Count; i++)
            {
                keys[i].Dispose();
            }
        }
    }
}
