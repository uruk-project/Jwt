// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-richer-vectors-of-trust-11
    /// </summary>
    public sealed class VectorOfTrust : IEnumerable<string>
    {
        private readonly Dictionary<char, List<char>> _vector = new Dictionary<char, List<char>>();

        public VectorOfTrust()
        {
        }

        public VectorOfTrust(string vector)
            : this((vector ?? throw new ArgumentNullException(nameof(vector))).AsSpan())
        {
        }

        public VectorOfTrust(ReadOnlySpan<char> vector)
        {
            if ((vector.Length + 1) % 3 != 0)
            {
                throw new ArgumentException(nameof(vector), "Invalid vector value. The length is incorrect.");
            }

            for (int i = 0; i < vector.Length; i++)
            {
                var dimension = vector[i++];
                var value = vector[i++];
                if (!char.IsUpper(dimension))
                {
                    throw new ArgumentException(nameof(vector), ErrorMessages.VotIncorrectDimension(dimension));
                }

                if (!char.IsLower(value) && !char.IsDigit(value))
                {
                    throw new ArgumentException(nameof(vector), ErrorMessages.VotIncorrectValue(value, dimension));
                }

                if (i != vector.Length && vector[i] != '.')
                {
                    throw new ArgumentException(nameof(vector), ErrorMessages.VotIncorrectSeparator(vector[i]));
                }

                if (_vector.TryGetValue(dimension, out var values))
                {
                    if (values.Contains(value))
                    {
                        throw new ArgumentException(nameof(vector), ErrorMessages.VotTooManyValues(dimension, value));
                    }

                    values.Add(value);
                }
                else
                {
                    _vector[dimension] = new List<char>() { value };
                }
            }
        }

        /// <summary>
        /// P
        /// </summary>
        public char[] IdentityProofing { get => this['P']; set => this['P'] = value; }

        /// <summary>
        /// C
        /// </summary>
        public char[] PrimaryCredentialUsage { get => this['C']; set => this['C'] = value; }

        /// <summary>
        /// M
        /// </summary>
        public char[] PrimaryCredentialManagement { get => this['M']; set => this['M'] = value; }

        /// <summary>
        /// A
        /// </summary>
        public char[] AssertionPresentation { get => this['A']; set => this['A'] = value; }

        public char[] this[char dimension]
        {
            get
            {
                if (_vector.TryGetValue(dimension, out var values))
                {
                    return values.ToArray();
                }

                return Array.Empty<char>();
            }

            set
            {
                _vector[dimension] = new List<char>(value);
            }
        }

        public override string ToString()
        {
            var stringBuilder = new StringBuilder();
            foreach (var value in this)
            {
                stringBuilder.Append(value).Append('.');
            }

            stringBuilder.Remove(stringBuilder.Length - 1, 1);
            return stringBuilder.ToString();
        }

        public IEnumerator<string> GetEnumerator()
        {
            foreach (var values in _vector)
            {
                for (int i = 0; i < values.Value.Count; i++)
                {
                    yield return string.Concat(values.Key, values.Value[i]);
                }
            }
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
