using System.Collections;
using System.Diagnostics;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the metadata of the JWT, like 
    /// like the cryptographic operations applied to the JWT and optionally 
    /// any additional properties of the JWT. 
    /// </summary>
    [DebuggerDisplay("{" + nameof(GetDebuggerDisplay) + "(),nq}")]
    public sealed class JwtHeader : IEnumerable
    {
        private readonly MemberStore _store = MemberStore.CreateSlowGrowingStore();

        /// <summary>
        /// Gets the count of parameters in the current header.
        /// </summary>
        public int Count => _store.Count;

        internal void CopyTo(JwtHeader destination)
        {
            _store.CopyTo(destination._store);
        }

        /// <summary>
        /// Adds a <see cref="string"/> as header parameters.
        /// </summary>
        /// <param name="propertyName"></param>
        /// <param name="value"></param>
        public void Add(string propertyName, string value)
        {
            _store.TryAdd(new JwtMember(propertyName, value));
        }

        /// <summary>
        /// Adds a <see cref="long"/> as header parameters.
        /// </summary>
        /// <param name="propertyName"></param>
        /// <param name="value"></param>
        public void Add(string propertyName, long value)
        {
            _store.TryAdd(new JwtMember(propertyName, value));
        }

        /// <summary>
        /// Adds an array of <see cref="object"/>s as header parameters.
        /// </summary>
        /// <param name="propertyName"></param>
        /// <param name="value"></param>
        public void Add(string propertyName, object[] value)
        {
            _store.TryAdd(new JwtMember(propertyName, value));
        }

        /// <summary>
        /// Adds an array of <see cref="string"/>s as header parameters.
        /// </summary>
        /// <param name="propertyName"></param>
        /// <param name="values"></param>
        public void Add(string propertyName, string?[] values)
        {
            _store.TryAdd(new JwtMember(propertyName, values));
        }

        /// <summary>
        /// Adds an <see cref="object"/> as header parameters.
        /// </summary>
        /// <param name="propertyName"></param>
        /// <param name="value"></param>
        public void Add(string propertyName, object value)
        {
            _store.TryAdd(new JwtMember(propertyName, value));
        }

        /// <summary>
        /// Adds an <see cref="bool"/> as header parameters.
        /// </summary>
        /// <param name="propertyName"></param>
        /// <param name="value"></param>
        public void Add(string propertyName, bool value)
        {
            _store.TryAdd(new JwtMember(propertyName, value));
        }

        internal void Add(JwtMember value)
        {
            _store.TryAdd(value);
        }

        internal bool TryGetValue(string utf8Name, out JwtMember value)
        {
            return _store.TryGetValue(utf8Name, out value);
        }


        /// <summary>
        /// Determines whether the <see cref="JwtHeader"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(string key)
        {
            return _store.ContainsKey(key);
        }

        internal void WriteTo(Utf8JsonWriter writer)
        {
            _store.WriteTo(writer);
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                _store.WriteTo(writer);
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }

        /// <inheritdoc/>
        public IEnumerator GetEnumerator()
        {
            return _store.GetEnumerator();
        }

        private string GetDebuggerDisplay()
        {
            return ToString();
        }
    }
}