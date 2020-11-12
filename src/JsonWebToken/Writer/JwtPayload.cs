// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Collections;
using System.Diagnostics;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the claims contained in the JWT.
    /// </summary>
    [DebuggerDisplay("{" + nameof(GetDebuggerDisplay) + "(),nq}")]
    public sealed class JwtPayload : IEnumerable
    {
        internal const byte InvalidAudienceFlag = 0x01;
        internal const byte MissingAudienceFlag = 0x02;
        internal const byte InvalidIssuerFlag = 0x04;
        internal const byte MissingIssuerFlag = 0x08;
        internal const byte ExpiredFlag = 0x10;
        internal const byte MissingExpirationFlag = 0x20;
        internal const byte NotYetFlag = 0x40;
   
        private readonly MemberStore _store;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class.
        /// </summary>
        public JwtPayload()
        {
            _store = MemberStore.CreateFastGrowingStore();
        }

        internal MemberStore Inner => _store;

        /// <summary>
        /// Gets the count of claims in the current payload.
        /// </summary>
        public int Count => _store.Count;

        internal void CopyTo(JwtPayload destination)
        {
            _store.CopyTo(destination._store);
        }

        /// <summary>
        /// Adds the value of the 'sub' claim.
        /// </summary>
        public void AddSub(string value)
            => _store.TryAdd(new JwtMember(Claims.Sub, value));

        /// <summary>
        /// Adds the value of the 'jti' claim.
        /// </summary>
        public void AddJti(string value)
            => _store.TryAdd(new JwtMember(Claims.Jti, value));

        /// <summary>
        /// Adds the value of the 'aud' claim.
        /// </summary>
        public void AddAud(string value)
            => _store.TryAdd(new JwtMember(Claims.Aud, value));

        /// <summary>
        /// Adds the value of the 'aud' claim.
        /// </summary>
        public void AddAud(string[] value)
            => _store.TryAdd(new JwtMember(Claims.Aud, value));

        /// <summary>
        /// Adds the value of the 'exp' claim.
        /// </summary>
        public void AddExp(long value)
            => _store.TryAdd(new JwtMember(Claims.Exp, value));

        /// <summary>
        /// Adds the value of the 'iss' claim.
        /// </summary>
        public void AddIss(string value)
            => _store.TryAdd(new JwtMember(Claims.Iss, value));

        /// <summary>
        /// Adds the value of the 'iat' claim.
        /// </summary>
        public void AddIat(string value)
            => _store.TryAdd(new JwtMember(Claims.Iat, value));

        /// <summary>
        ///Adds the value of the 'nbf' claim.
        /// </summary>
        public void AddNbf(long value)
            => _store.TryAdd(new JwtMember(Claims.Nbf, value));

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
                _store.WriteTo(writer);
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }

        internal void Add(JwtMember value)
        {
            _store.TryAdd(value);
        }

        /// <summary>
        /// Adds the claim of type <see cref="string"/> to the current <see cref="JwtPayload"/>.
        /// </summary>
        public void Add(string claimName, string value)
        {
            _store.TryAdd(new JwtMember(claimName, value));
        }

        /// <summary>
        /// Adds the claim of type <see cref="long"/> to the current <see cref="JwtPayload"/>.
        /// </summary>
        public void Add(string claimName, long value)
        {
            _store.TryAdd(new JwtMember(claimName, value));
        }

        /// <summary>
        /// Adds the claim of type <see cref="int"/> to the current <see cref="JwtPayload"/>.
        /// </summary>
        public void Add(string claimName, int value)
        {
            _store.TryAdd(new JwtMember(claimName, value));
        }

        /// <summary>
        /// Adds the claim of type <see cref="int"/> to the current <see cref="JwtPayload"/>.
        /// </summary>
        public void Add(string claimName, short value)
        {
            _store.TryAdd(new JwtMember(claimName, value));
        }

        /// <summary>
        /// Adds the claim of type array of <see cref="object"/> to the current <see cref="JwtPayload"/>.
        /// </summary>
        public void Add(string claimName, object[] value)
        {
            _store.TryAdd(new JwtMember(claimName, value));
        }

        /// <summary>
        /// Adds the claim of type array of <see cref="string"/> to the current <see cref="JwtPayload"/>.
        /// </summary>
        public void Add(string claimName, string?[] values)
        {
            _store.TryAdd(new JwtMember(claimName, values));
        }

        /// <summary>
        /// Adds the claim of type <see cref="bool"/> to the current <see cref="JwtPayload"/>.
        /// </summary>
        public void Add(string claimName, bool value)
        {
            _store.TryAdd(new JwtMember(claimName, value));
        }

        /// <summary>
        /// Adds the claim of type <see cref="object"/> to the current <see cref="JwtPayload"/>.
        /// </summary>
        public void Add(string claimName, object value)
        {
            _store.TryAdd(new JwtMember(claimName, value));
        }

        /// <inheritdoc/>
        public IEnumerator GetEnumerator()
        {
            return _store.GetEnumerator();
        }

        internal void WriteTo(Utf8JsonWriter writer)
        {
            _store.WriteTo(writer);
        }

        private string GetDebuggerDisplay()
        {
            return ToString();
        }
    }
}