using System.Collections;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the metadata of the JWT, like 
    /// like the cryptographic operations applied to the JWT and optionally 
    /// any additional properties of the JWT. 
    /// </summary>
    public sealed class JwtHeader : IEnumerable
    {
        private readonly MemberStore _header = MemberStore.CreateForHeader();

        /// <summary>
        /// Gets the count of parameters in the current header.
        /// </summary>
        public int Count => _header.Count;

        internal void CopyTo(JwtHeader destination)
        {
            _header.CopyTo(destination._header);
        }

        /// <summary>
        /// Adds a <see cref="string"/> as header parameters.
        /// </summary>
        /// <param name="propertyName"></param>
        /// <param name="value"></param>
        public void Add(string propertyName, string value)
        {
            _header.TryAdd(new JwtMemberX(propertyName, value));
        }

        /// <summary>
        /// Adds a <see cref="long"/> as header parameters.
        /// </summary>
        /// <param name="propertyName"></param>
        /// <param name="value"></param>
        public void Add(string propertyName, long value)
        {
            _header.TryAdd(new JwtMemberX(propertyName, value));
        }

        /// <summary>
        /// Adds an array of <see cref="object"/>s as header parameters.
        /// </summary>
        /// <param name="propertyName"></param>
        /// <param name="value"></param>
        public void Add(string propertyName, object[] value)
        {
            _header.TryAdd(new JwtMemberX(propertyName, value));
        }

        /// <summary>
        /// Adds an array of <see cref="string"/>s as header parameters.
        /// </summary>
        /// <param name="propertyName"></param>
        /// <param name="values"></param>
        public void Add(string propertyName, string?[] values)
        {
            _header.TryAdd(new JwtMemberX(propertyName, values));
        }

        /// <summary>
        /// Adds an <see cref="object"/> as header parameters.
        /// </summary>
        /// <param name="propertyName"></param>
        /// <param name="value"></param>
        public void Add(string propertyName, object value)
        {
            _header.TryAdd(new JwtMemberX(propertyName, value));
        }

        /// <summary>
        /// Adds an <see cref="bool"/> as header parameters.
        /// </summary>
        /// <param name="propertyName"></param>
        /// <param name="value"></param>
        public void Add(string propertyName, bool value)
        {
            _header.TryAdd(new JwtMemberX(propertyName, value));
        }

        internal void Add(JwtMemberX value)
        {
            _header.TryAdd(value);
        }

        internal bool TryGetValue(string utf8Name, out JwtMemberX value)
        {
            return _header.TryGetValue(utf8Name, out value);
        }

        internal void WriteTo(Utf8JsonWriter writer)
        {
            _header.WriteTo(writer);
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                _header.WriteTo(writer);
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }

        /// <inheritdoc/>
        public IEnumerator GetEnumerator()
        {
            return ((IEnumerable)_header).GetEnumerator();
        }
    }
}