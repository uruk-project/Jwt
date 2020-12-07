using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Represents the header of a JWT, in a lightweight, read-only form. </summary>
    /// <remarks>
    /// This class utilizes resources from pooled memory to minimize the garbage collector (GC)
    /// impact in high-usage scenarios. Failure to properly Dispose this object will result in
    /// the memory not being returned to the pool.
    /// </remarks>
    // Based on https://github.com/dotnet/runtime/blob/master/src/libraries/System.Text.Json/src/System/Text/Json/Document/JsonDocument.cs
    public sealed class JwtHeaderDocument : IDisposable
    {
        internal static readonly JwtHeaderDocument Empty = new JwtHeaderDocument(new JwtDocument(), -1, -1, -1);

        private readonly JwtDocument _document;
        private readonly JwtElement _alg;
        private readonly JwtElement _enc;
        private readonly JwtElement _kid;

        /// <inheritdoc/>
        internal JwtElement Kid => _kid;

        internal JwtElement Alg => _alg;

        internal JwtElement Enc => _enc;

        private JwtHeaderDocument(JwtDocument document, int algIdx, int encIdx, int kidIdx)
        {
            _document = document;
            _alg = algIdx < 0 ? default : new JwtElement(_document, algIdx);
            _enc = encIdx < 0 ? default : new JwtElement(_document, encIdx);
            _kid = kidIdx < 0 ? default : new JwtElement(_document, kidIdx);
        }

        internal static bool TryParseHeader(ReadOnlyMemory<byte> utf8Payload, byte[]? buffer, TokenValidationPolicy policy, [NotNullWhen(true)] out JwtHeaderDocument? header, [NotNullWhen(false)] out TokenValidationError? error)
        {
            ReadOnlySpan<byte> utf8JsonSpan = utf8Payload.Span;
            var database = new JsonMetadata(utf8Payload.Length);
            int algIdx = -1;
            int encIdx = -1;
            int kidIdx = -1;

            var reader = new Utf8JsonReader(utf8JsonSpan);

            if (reader.Read())
            {
                JsonTokenType tokenType = reader.TokenType;
                if (tokenType == JsonTokenType.StartObject)
                {
                    while (reader.Read())
                    {
                        tokenType = reader.TokenType;
                        int tokenStart = (int)reader.TokenStartIndex;

                        if (tokenType == JsonTokenType.EndObject)
                        {
                            break;
                        }
                        else if (tokenType != JsonTokenType.PropertyName)
                        {
                            error = TokenValidationError.MalformedToken();
                            goto Error;
                        }

                        // Adding 1 to skip the start quote will never overflow
                        Debug.Assert(tokenStart < int.MaxValue);

                        database.Append(JsonTokenType.PropertyName, tokenStart + 1, reader.ValueSpan.Length);
                        if (reader.ValueSpan.IndexOf((byte)'\\') != -1)
                        {
                            database.SetNeedUnescaping(database.Length - JsonRow.Size);
                        }

                        ReadOnlySpan<byte> memberName = reader.ValueSpan;

                        reader.Read();
                        tokenType = reader.TokenType;
                        tokenStart = (int)reader.TokenStartIndex;

                        // Since the input payload is contained within a Span,
                        // token start index can never be larger than int.MaxValue (i.e. utf8JsonSpan.Length).
                        Debug.Assert(reader.TokenStartIndex <= int.MaxValue);
                        if (tokenType == JsonTokenType.String)
                        {
                            if (memberName.Length == 3)
                            {
                                switch ((JwtHeaderParameters)IntegerMarshal.ReadUInt24(memberName))
                                {
                                    case JwtHeaderParameters.Alg:
                                        algIdx = database.Length;
                                        break;
                                    case JwtHeaderParameters.Enc:
                                        encIdx = database.Length;
                                        break;
                                    case JwtHeaderParameters.Kid:
                                        kidIdx = database.Length;
                                        break;
                                }
                            }

                            // Adding 1 to skip the start quote will never overflow
                            Debug.Assert(tokenStart < int.MaxValue);
                            database.Append(JsonTokenType.String, tokenStart + 1, reader.ValueSpan.Length);
                        }
                        else if (tokenType == JsonTokenType.StartObject)
                        {
                            int count = Utf8JsonReaderHelper.SkipObject(ref reader);
                            int index = database.Length;
                            int tokenEnd = (int)reader.TokenStartIndex;
                            database.Append(JsonTokenType.StartObject, tokenStart, tokenEnd - tokenStart + 1);
                            database.SetNumberOfRows(index, count);
                        }
                        else if (tokenType == JsonTokenType.StartArray)
                        {
                            int count;
                            if (memberName.Length == 4
                                && (JwtHeaderParameters)IntegerMarshal.ReadUInt32(memberName) == JwtHeaderParameters.Crit
                                && !policy.IgnoreCriticalHeader)
                            {
                                if (!TryCheckCrit(ref reader, out count))
                                {
                                    error = TokenValidationError.MalformedToken("The 'crit' header parameter must be an array of string.");
                                    goto Error;
                                }
                            }
                            else
                            {
                                count = Utf8JsonReaderHelper.SkipArray(ref reader);
                            }

                            int index = database.Length;
                            int tokenEnd = (int)reader.TokenStartIndex;
                            database.Append(JsonTokenType.StartArray, tokenStart, tokenEnd - tokenStart + 1);
                            database.SetNumberOfRows(index, count);
                        }
                        else
                        {
                            Debug.Assert(tokenType >= JsonTokenType.Number && tokenType <= JsonTokenType.Null);
                            database.Append(tokenType, tokenStart, reader.ValueSpan.Length);
                        }
                    }
                }
            }

            Debug.Assert(reader.BytesConsumed == utf8JsonSpan.Length);
            database.CompleteAllocations();

            header = new JwtHeaderDocument(new JwtDocument(utf8Payload, database, buffer), algIdx, encIdx, kidIdx);
            error = null;
            return true;

        Error:
            header = null;
            return false;
        }

        /// <summary>
        ///   Looks for a header parameter named <paramref name="headerParameterName"/> in the current JWT, returning
        ///   whether or not such a parameter existed. When the parameter exists <paramref name="value"/>
        ///   is assigned to the value of that parameter.
        /// </summary>
        /// <param name="headerParameterName">Name of the header parameter to find.</param>
        /// <param name="value">Receives the value of the located parameter.</param>
        /// <returns>
        ///   <see langword="true"/> if the parameter was found, <see langword="false"/> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        public bool TryGetHeaderParameter(string headerParameterName, out JwtElement value)
            => _document.TryGetProperty(headerParameterName, out value);

        /// <summary>
        ///   Looks for a header parameter named <paramref name="headerParameterName"/> in the current JWT, returning
        ///   whether or not such a parameter existed. When the parameter exists <paramref name="value"/>
        ///   is assigned to the value of that parameter.
        /// </summary>
        /// <param name="headerParameterName">Name of the parameter to find.</param>
        /// <param name="value">Receives the value of the located parameter.</param>
        /// <returns>
        ///   <see langword="true"/> if the parameter was found, <see langword="false"/> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        public bool TryGetHeaderParameter(JsonEncodedText headerParameterName, out JwtElement value)
            => _document.TryGetProperty(headerParameterName.EncodedUtf8Bytes, out value);
        
        /// <summary>
        ///   Looks for a header parameter named <paramref name="headerParameterName"/> in the current JWT, returning
        ///   whether or not such a parameter existed. When the parameter exists <paramref name="value"/>
        ///   is assigned to the value of that parameter.
        /// </summary>
        /// <param name="headerParameterName">Name of the parameter to find.</param>
        /// <param name="value">Receives the value of the located parameter.</param>
        /// <returns>
        ///   <see langword="true"/> if the parameter was found, <see langword="false"/> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        public bool TryGetHeaderParameter(ReadOnlySpan<byte> headerParameterName, out JwtElement value)
            => _document.TryGetProperty(headerParameterName, out value);

        private static bool TryCheckCrit(ref Utf8JsonReader reader, out int count)
        {
            count = 0;
            bool result = true;
            while (reader.Read() && reader.TokenType == JsonTokenType.String)
            {
                // just read...
                count++;
            }

            if (reader.TokenType != JsonTokenType.EndArray)
            {
                result = false;
            }

            return result;
        }

        /// <inheritdoc />
        public void Dispose()
            => _document.Dispose();

        /// <summary>Gets a <see cref="JwtHeaderDocument"/> which can be safely stored beyond the lifetime of the original object.</summary>
        /// <returns></returns>
        public JwtHeaderDocument Clone()
            => new JwtHeaderDocument(
                _document.Clone(),
                _alg.ValueKind == JsonValueKind.Undefined ? -1 : _alg.Idx,
                _enc.ValueKind == JsonValueKind.Undefined ? -1 : _enc.Idx,
                _kid.ValueKind == JsonValueKind.Undefined ? -1 : _kid.Idx);

        /// <summary>Determines whether the <see cref="JwtHeaderDocument"/> contains the specified header parameter.</summary>
        /// <param name="headerParameterName"></param>
        /// <returns></returns>
        public bool ContainsHeaderParameter(string headerParameterName)
            =>  _document.ContainsKey(headerParameterName);

        /// <summary>Determines whether the <see cref="JwtHeaderDocument"/> contains the specified header parameter.</summary>
        /// <param name="headerParameterName"></param>
        /// <returns></returns>
        public bool ContainsHeaderParameter(ReadOnlySpan<byte> headerParameterName)
            => _document.ContainsKey(headerParameterName);

        /// <summary>
        ///   Looks for a header parameter named <paramref name="name"/> in the current JWT header, returning
        ///   the value of that parameter.
        /// </summary>
        /// <param name="name">Name of the parameter to find.</param>
        /// <returns>
        ///  The value of the located parameter.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="KeyNotFoundException">
        ///   The <paramref name="name"/> is not found.
        /// </exception>
        public JwtElement this[string name]
        {
            get
            {
                if (_document.TryGetProperty(name, out var value))
                {
                    return value;
                }

                throw new KeyNotFoundException();
            }
        }

        /// <summary>
        ///   Looks for a header parameter named <paramref name="name"/> in the current JWT header, returning
        ///   the value of that parameter.
        /// </summary>
        /// <param name="name">Name of the parameter to find.</param>
        /// <returns>
        ///  The value of the located parameter.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="KeyNotFoundException">
        ///   The <paramref name="name"/> is not found.
        /// </exception>
        public JwtElement this[ReadOnlySpan<byte> name]
        {
            get
            {
                if (_document.TryGetProperty(name, out var value))
                {
                    return value;
                }

                throw new KeyNotFoundException();
            }
        }

        /// <inheritdoc/>
        public override string ToString()
            => _document.ToString();
    }
}