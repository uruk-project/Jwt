// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Contains a collection of <see cref="Jwk"/>.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public sealed class Jwks : IDisposable, IEnumerable<Jwk>
    {
        private const uint keys = 1937335659u;
        private readonly List<Jwk> _keys = new List<Jwk>();

        private KeyValuePair<JsonEncodedText, Jwk[]>[]? _identifiedKeys;

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
                    if (kid == key.Kid.ToString())
                    {
                        return key;
                    }
                }

                return null;
            }
        }

        /// <summary>
        /// Gets or sets the first <see cref="Jwk"/> with its 'kid'.
        /// </summary>
        public Jwk? this[JsonEncodedText kid]
        {
            get
            {
                var keys = _keys;
                for (int i = 0; i < keys.Count; i++)
                {
                    var key = keys[i];
                    if (kid.EncodedUtf8Bytes.SequenceEqual(key.Kid.EncodedUtf8Bytes))
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
            writer.WriteStartArray(JwksParameterNames.Keys);
            var keys = _keys;
            for (int i = 0; i < keys.Count; i++)
            {
                keys[i].WriteTo(writer);
            }

            writer.WriteEndArray();
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

        internal KeyValuePair<JsonEncodedText, Jwk[]>[] GetIdentifiedKeys()
        {
            if (_identifiedKeys is null)
            {
                if (_keys.Count == 1)
                {
                    var key1 = _keys[0];
                    if (key1.Kid.EncodedUtf8Bytes.IsEmpty)
                    {
                        _identifiedKeys = Array.Empty<KeyValuePair<JsonEncodedText, Jwk[]>>();
                    }
                    else
                    {
                        _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[1]
                        {
                                new KeyValuePair<JsonEncodedText, Jwk[]>(key1.Kid, new[] { key1 })
                        };
                    }
                }
                else if (_keys.Count == 2)
                {
                    var key2 = _keys[1];
                    var key1 = _keys[0];
                    if (key1.Kid.Equals(key2.Kid))
                    {
                        if (key1.Kid.EncodedUtf8Bytes.IsEmpty)
                        {
                            _identifiedKeys = Array.Empty<KeyValuePair<JsonEncodedText, Jwk[]>>();
                        }
                        else
                        {
                            _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[1]
                            {
                                    new KeyValuePair<JsonEncodedText, Jwk[]>(key1.Kid, new[] { key1, key2 })
                            };
                        }
                    }
                    else
                    {
                        if (key1.Kid.EncodedUtf8Bytes.IsEmpty)
                        {
                            _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[1]
                            {
                                    new KeyValuePair<JsonEncodedText, Jwk[]>(key2.Kid, new[] { key2, key1 })
                            };
                        }
                        else if (key2.Kid.EncodedUtf8Bytes.IsEmpty)
                        {
                            _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[1]
                            {
                                    new KeyValuePair<JsonEncodedText, Jwk[]>(key1.Kid, new[] { key1, key2 })
                            };
                        }
                        else
                        {
                            _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[2]
                            {
                                    new KeyValuePair<JsonEncodedText, Jwk[]>(key1.Kid, new[] { key1 }),
                                    new KeyValuePair<JsonEncodedText, Jwk[]>(key2.Kid, new[] { key2 })
                            };
                        }
                    }
                }
                else if (_keys.Count == 3)
                {
                    var key3 = _keys[2];
                    var key2 = _keys[1];
                    var key1 = _keys[0];
                    if (key1.Kid.Equals(key2.Kid))
                    {
                        if (key1.Kid.Equals(key3.Kid))
                        {
                            if (key1.Kid.EncodedUtf8Bytes.IsEmpty)
                            {
                                _identifiedKeys = Array.Empty<KeyValuePair<JsonEncodedText, Jwk[]>>();
                            }
                            else
                            {
                                _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[1]
                                {
                                        new KeyValuePair<JsonEncodedText, Jwk[]>(key1.Kid, new[] { key1, key2, key3 })
                                };
                            }
                        }
                        else
                        {
                            if (key1.Kid.EncodedUtf8Bytes.IsEmpty)
                            {
                                _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[1]
                                {
                                        new KeyValuePair<JsonEncodedText, Jwk[]>(key3.Kid, new[] { key3, key1, key2 })
                                };
                            }
                            else if (key3.Kid.EncodedUtf8Bytes.IsEmpty)
                            {
                                _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[1]
                                {
                                        new KeyValuePair<JsonEncodedText, Jwk[]>(key1.Kid, new[] { key1, key2, key3 })
                                };
                            }
                            else
                            {
                                _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[2]
                                {
                                        new KeyValuePair<JsonEncodedText, Jwk[]>(key1.Kid, new[] { key1, key2 }),
                                        new KeyValuePair<JsonEncodedText, Jwk[]>(key3.Kid, new[] { key3 })
                                };
                            }
                        }
                    }
                    else
                    {
                        if (key2.Kid.Equals(key3.Kid))
                        {
                            if (key1.Kid.EncodedUtf8Bytes.IsEmpty)
                            {
                                _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[1]
                                {
                                        new KeyValuePair<JsonEncodedText, Jwk[]>(key2.Kid, new[] { key2, key3, key1 })
                                };
                            }
                            else if (key2.Kid.EncodedUtf8Bytes.IsEmpty)
                            {
                                _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[1]
                                {
                                        new KeyValuePair<JsonEncodedText, Jwk[]>(key1.Kid, new[] { key1, key2, key3 })
                                };
                            }
                            else
                            {
                                _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[2]
                                {
                                        new KeyValuePair<JsonEncodedText, Jwk[]>(key1.Kid, new[] { key1 }),
                                        new KeyValuePair<JsonEncodedText, Jwk[]>(key2.Kid, new[] { key2, key3 })
                                };
                            }
                        }
                        else
                        {
                            if (key1.Kid.Equals(key3.Kid))
                            {
                                if (key1.Kid.EncodedUtf8Bytes.IsEmpty)
                                {
                                    _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[1]
                                    {
                                            new KeyValuePair<JsonEncodedText, Jwk[]>(key2.Kid, new[] { key2, key1, key3 })
                                    };
                                }
                                else if (key2.Kid.EncodedUtf8Bytes.IsEmpty)
                                {
                                    _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[1]
                                    {
                                            new KeyValuePair<JsonEncodedText, Jwk[]>(key1.Kid, new[] { key1, key3, key2 })
                                    };
                                }
                                else
                                {
                                    _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[2]
                                    {
                                            new KeyValuePair<JsonEncodedText, Jwk[]>(key1.Kid, new[] { key1, key3 }),
                                            new KeyValuePair<JsonEncodedText, Jwk[]>(key2.Kid, new[] { key2 })
                                    };
                                }
                            }
                            else
                            {
                                if (key1.Kid.EncodedUtf8Bytes.IsEmpty)
                                {
                                    _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[2]
                                    {
                                            new KeyValuePair<JsonEncodedText, Jwk[]>(key2.Kid, new[] { key2, key1 }),
                                            new KeyValuePair<JsonEncodedText, Jwk[]>(key3.Kid, new[] { key3, key1 })
                                    };
                                }
                                else if (key2.Kid.EncodedUtf8Bytes.IsEmpty)
                                {
                                    _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[2]
                                    {
                                            new KeyValuePair<JsonEncodedText, Jwk[]>(key1.Kid, new[] { key1, key2 }),
                                            new KeyValuePair<JsonEncodedText, Jwk[]>(key3.Kid, new[] { key3, key2 })
                                    };
                                }
                                else if (key3.Kid.EncodedUtf8Bytes.IsEmpty)
                                {
                                    _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[2]
                                    {
                                            new KeyValuePair<JsonEncodedText, Jwk[]>(key1.Kid, new[] { key1, key3 }),
                                            new KeyValuePair<JsonEncodedText, Jwk[]>(key2.Kid, new[] { key2, key3 })
                                    };
                                }
                                else
                                {
                                    _identifiedKeys = new KeyValuePair<JsonEncodedText, Jwk[]>[3]
                                    {
                                            new KeyValuePair<JsonEncodedText, Jwk[]>(key1.Kid, new[] { key1 }),
                                            new KeyValuePair<JsonEncodedText, Jwk[]>(key2.Kid, new[] { key2 }),
                                            new KeyValuePair<JsonEncodedText, Jwk[]>(key3.Kid, new[] { key3 })
                                    };
                                }
                            }
                        }
                    }
                }
                else if (_keys.Count == 0)
                {
                    _identifiedKeys = Array.Empty<KeyValuePair<JsonEncodedText, Jwk[]>>();
                }
                else
                {
                    var unidentified = _keys.Where(jwk => jwk.Kid.EncodedUtf8Bytes.IsEmpty);
                    _identifiedKeys = _keys
                                        .GroupBy(k => k.Kid)
                                        .Where(k => !k.Key.EncodedUtf8Bytes.IsEmpty)
                                        .ToDictionary(k => k.Key, k => k.Concat(unidentified).ToArray())
                                        .ToArray();
                    
                }
            }

            return _identifiedKeys;
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
        public Jwk[] GetKeys(JwtElement kid)
        {
            if (kid.IsEmpty)
            {
                return _keys.ToArray();
            }

            var keys = GetIdentifiedKeys();
            for (int i = 0; i < keys.Length; i++)
            {
                var key = keys[i];
                if (kid.ValueEquals(key.Key.EncodedUtf8Bytes))
                {
                    return key.Value;
                }
            }

            return Array.Empty<Jwk>();
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

            if (reader.Read() && reader.TokenType is JsonTokenType.StartObject && reader.Read())
            {
                while (reader.TokenType is JsonTokenType.PropertyName)
                {
                    var propertyName = reader.ValueSpan;
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

                            continue;
                        }
                    }

                    reader.Read();
                    if (reader.TokenType >= JsonTokenType.String && reader.TokenType <= JsonTokenType.Null)
                    {
                        reader.Read();
                    }
                    else if (reader.TokenType == JsonTokenType.StartObject)
                    {
                        JsonParser.ConsumeJsonObject(ref reader);
                    }
                    else if (reader.TokenType == JsonTokenType.StartArray)
                    {
                        JsonParser.ConsumeJsonArray(ref reader);
                    }
                    else
                    {
                        ThrowHelper.ThrowInvalidOperationException_MalformedJwks();
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

        /// <inheritdoc/>
        public IEnumerator<Jwk> GetEnumerator()
        {
            return ((IEnumerable<Jwk>)_keys).GetEnumerator();
        }

        /// <inheritdoc/>
        IEnumerator IEnumerable.GetEnumerator()
        {
            return ((IEnumerable)_keys).GetEnumerator();
        }
    }
}
