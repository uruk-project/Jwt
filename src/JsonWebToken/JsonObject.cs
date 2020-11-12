// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Collections;
using System.Diagnostics;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the a JSON object.
    /// </summary>
    [DebuggerDisplay("{" + nameof(GetDebuggerDisplay) + "(),nq}")]
    public class JsonObject : IEnumerable, IJwtSerializable
    {
        private readonly MemberStore _store;

        /// <summary>
        /// Initializes a new instance of the <see cref="JsonObject"/> class.
        /// </summary>
        public JsonObject()
        {
            _store = MemberStore.CreateSlowGrowingStore();
        }

        /// <summary>
        /// Gets the member store used to keep track of JSON key-values.
        /// </summary>
        protected MemberStore Store => _store;

        internal void CopyTo(JsonObject destination)
        {
            _store.CopyTo(destination._store);
        }

        /// <summary>
        /// Determines whether the <see cref="JwtPayload"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(string key)
        {
            return _store.ContainsKey(key);
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        public bool TryGetValue(string key, out JwtMember value)
        {
            return _store.TryGetValue(key, out value);
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

        internal void Add(JwtMember value)
        {
            _store.TryAdd(value);
        }

        /// <summary>
        /// Adds the claim of type <see cref="object"/> to the current <see cref="JwtPayload"/>.
        /// </summary>
        public void Add(string claimName, object value)
        {
            _store.TryAdd(new JwtMember(claimName, value));
        }

        /// <summary>
        /// Adds the claim of type <see cref="object"/> to the current <see cref="JwtPayload"/>.
        /// </summary>
        public void Add(string name, JsonObject jsonObject)
        {
            _store.TryAdd(new JwtMember(name, jsonObject));
        }

        /// <inheritdoc/>
        public IEnumerator GetEnumerator()
        {
            return _store.GetEnumerator();
        }

        /// <inheritdoc/>
        public void WriteTo(Utf8JsonWriter writer)
        {
            _store.WriteTo(writer);
        }

        private string GetDebuggerDisplay()
        {
            return ToString();
        }
    }
}
