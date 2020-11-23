// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Represents the a JSON object.</summary>
    [DebuggerDisplay("{" + nameof(GetDebuggerDisplay) + "(),nq}")]
    public class JsonObject : IEnumerable, IEnumerable<JwtMember>, IJwtSerializable
    {
        private readonly MemberStore _store;

        /// <summary>Initializes a new instance of the <see cref="JsonObject"/> class.</summary>
        public JsonObject()
        {
            _store = MemberStore.CreateSlowGrowingStore();
        }

        /// <summary>Initializes a new instance of the <see cref="JsonObject"/> class.</summary>
        private protected JsonObject(MemberStore store)
        {
            _store = store;
        }

        /// <summary>Gets the number of items in the current <see cref="JsonObject"/>.</summary>
        public int Count => _store.Count;

        internal void CopyTo(JsonObject destination)
            => _store.CopyTo(destination._store);

        /// <summary>Determines whether the <see cref="JsonObject"/> contains the specified key.</summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(JsonEncodedText key)
            => _store.ContainsKey(key);

        /// <summary>Gets the value associated with the specified key.</summary>
        public bool TryGetValue(JsonEncodedText key, out JwtMember value)
            => _store.TryGetValue(key, out value);

        /// <summary>Gets the value associated with the specified key.</summary>
        public bool TryGetValue(string key, out JwtMember value)
            => _store.TryGetValue(JsonEncodedText.Encode(key), out value);

        /// <summary>Adds the value of type <see cref="object"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(string name, object value)
            => _store.Add(new JwtMember(JsonEncodedText.Encode(name), value));

        /// <summary>Adds the value of type <see cref="object"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(string name, JsonObject jsonObject)
            => _store.Add(new JwtMember(JsonEncodedText.Encode(name), jsonObject));

        /// <summary>Adds the value of type <see cref="string"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(string name, string value)
            => _store.Add(new JwtMember(JsonEncodedText.Encode(name), value));

        /// <summary>Adds the value of type <see cref="string"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(string name, JsonEncodedText value)
            => _store.Add(new JwtMember(JsonEncodedText.Encode(name), value));

        /// <summary>Adds the value of type <see cref="long"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(string name, long value)
            => _store.Add(new JwtMember(JsonEncodedText.Encode(name), value));

        /// <summary>Adds the value of type <see cref="int"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(string name, int value)
            => _store.Add(new JwtMember(JsonEncodedText.Encode(name), value));

        /// <summary>Adds the value of type <see cref="ulong"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(string name, ulong value)
            => _store.Add(new JwtMember(JsonEncodedText.Encode(name), value));

        /// <summary>Adds the value of type <see cref="uint"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(string name, uint value)
            => _store.Add(new JwtMember(JsonEncodedText.Encode(name), value));

        /// <summary>Adds the value of type <see cref="float"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(string name, float value)
            => _store.Add(new JwtMember(JsonEncodedText.Encode(name), value));

        /// <summary>Adds the value of type <see cref="double"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(string name, double value)
            => _store.Add(new JwtMember(JsonEncodedText.Encode(name), value));

        /// <summary>Adds the value of type array of <see cref="object"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(string name, object[] value)
            => _store.Add(new JwtMember(JsonEncodedText.Encode(name), value));

        /// <summary>Adds the value of type array of <see cref="string"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(string name, string?[] values)
            => _store.Add(new JwtMember(JsonEncodedText.Encode(name), values));

        /// <summary>Adds the value of type <see cref="bool"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(string name, bool value)
            => _store.Add(new JwtMember(JsonEncodedText.Encode(name), value));

        /// <summary>Adds the value of type <see cref="JsonEncodedText"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(JsonEncodedText name, JsonEncodedText value)
            => _store.Add(new JwtMember(name, value));

        /// <summary>Adds the value of type <see cref="object"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(JsonEncodedText name, object value)
            => _store.Add(new JwtMember(name, value));

        /// <summary>Adds the value of type <see cref="object"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(JsonEncodedText name, JsonObject jsonObject)
            => _store.Add(new JwtMember(name, jsonObject));

        /// <summary>Adds the value of type <see cref="string"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(JsonEncodedText name, string value)
            => _store.Add(new JwtMember(name, value));

        /// <summary>Adds the value of type <see cref="long"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(JsonEncodedText name, long value)
            => _store.Add(new JwtMember(name, value));

        /// <summary>Adds the value of type <see cref="int"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(JsonEncodedText name, int value)
            => _store.Add(new JwtMember(name, value));

        /// <summary>Adds the value of type <see cref="ulong"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(JsonEncodedText name, ulong value)
            => _store.Add(new JwtMember(name, value));

        /// <summary>Adds the value of type <see cref="uint"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(JsonEncodedText name, uint value)
            => _store.Add(new JwtMember(name, value));

        /// <summary>Adds the value of type <see cref="float"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(JsonEncodedText name, float value)
            => _store.Add(new JwtMember(name, value));

        /// <summary>Adds the value of type <see cref="double"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(JsonEncodedText name, double value)
            => _store.Add(new JwtMember(name, value));

        /// <summary>Adds the value of type array of <see cref="object"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(JsonEncodedText name, object[] value)
            => _store.Add(new JwtMember(name, value));

        /// <summary>Adds the value of type array of <see cref="string"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(JsonEncodedText name, string?[] values)
            => _store.Add(new JwtMember(name, values));

        /// <summary>Adds the value of type <see cref="bool"/> to the current <see cref="JsonObject"/>.</summary>
        public void Add(JsonEncodedText name, bool value)
            => _store.Add(new JwtMember(name, value));

        /// <inheritdoc/>
        IEnumerator IEnumerable.GetEnumerator()
            => GetEnumerator();

        /// <inheritdoc/>
        public IEnumerator<JwtMember> GetEnumerator()
            => _store.GetEnumerator();

        /// <inheritdoc/>
        public void WriteTo(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            _store.WriteTo(writer);
            writer.WriteEndObject();
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();
                _store.WriteTo(writer);
                writer.WriteEndObject();
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }

        private string GetDebuggerDisplay()
            => ToString();
    }
}
