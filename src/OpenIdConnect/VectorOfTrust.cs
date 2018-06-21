using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-richer-vectors-of-trust-11
    /// </summary>
    public class VectorOfTrust : IEnumerable<string>
    {
        private readonly IDictionary<char, IList<char>> _vector = new Dictionary<char, IList<char>>();

        public VectorOfTrust()
        {
        }

        public VectorOfTrust(ReadOnlySpan<char> vector)
        {
            if (vector == null || vector.IsEmpty)
            {
                throw new ArgumentNullException(nameof(vector));
            }

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
                    throw new ArgumentException(nameof(vector), ErrorMessages.FormatInvariant("Invalid vector value. The dimension '{0}' is not valid.", dimension));
                }

                if (!char.IsLower(value) && !char.IsDigit(value))
                {
                    throw new ArgumentException(nameof(vector), ErrorMessages.FormatInvariant("Invalid vector value. The value '{0}' for dimension '{1}' is not valid. Must be a lowercase letter [a-z] or a single digit [0-9].", value, dimension));
                }

                if (i != vector.Length && vector[i] != '.')
                {
                    throw new ArgumentException(nameof(vector), ErrorMessages.FormatInvariant("Invalid vector value. The separator '{0}' is not valid. Should be '.'.", vector[i]));
                }

                if (_vector.TryGetValue(dimension, out var values))
                {
                    if (values.Contains(value))
                    {
                        throw new ArgumentException(nameof(vector), ErrorMessages.FormatInvariant("Invalid vector value. The dimension '{0}' define the value '{1}' more than once.", dimension, value));
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
        public IList<char> IdentityProofing { get => this['P']; set => this['P'] = value; }

        /// <summary>
        /// C
        /// </summary>
        public IList<char> PrimaryCredentialUsage { get => this['C']; set => this['C'] = value; }

        /// <summary>
        /// M
        /// </summary>
        public IList<char> PrimaryCredentialManagement { get => this['M']; set => this['M'] = value; }

        /// <summary>
        /// A
        /// </summary>
        public IList<char> AssertionPresentation { get => this['A']; set => this['A'] = value; }

        public IList<char> this[char dimension]
        {
            get
            {
                if (_vector.TryGetValue(dimension, out var values))
                {
                    return values;
                }

                return null;
            }

            set
            {
                _vector[dimension] = value;
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
