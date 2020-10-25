using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    public sealed class JwtHeaderDocument : IJwtHeader, IDisposable
    {
        private readonly JwtDocument _document;
        private readonly JwtElement _root;
        private readonly JwtElement _alg;
        private readonly JwtElement _kid;

#if SUPPORT_ELLIPTIC_CURVE
        public ECJwk? Epk => _root.TryGetProperty(HeaderParameters.EpkUtf8, out var epk) ? ECJwk.FromJwtElement(epk) : null;

        public string? Apu => _root.TryGetProperty(HeaderParameters.ApuUtf8, out var apu) ? apu.GetString() : null;

        public string? Apv => _root.TryGetProperty(HeaderParameters.ApvUtf8, out var apv) ? apv.GetString() : null;
#endif
        public string? IV => _root.TryGetProperty(HeaderParameters.IVUtf8, out var iv) ? iv.GetString() : null;

        public string? Tag => _root.TryGetProperty(HeaderParameters.TagUtf8, out var tag) ? tag.GetString() : null;

        public string? Kid => _kid.GetString();//_root.TryGetProperty(HeaderParameters.KidUtf8, out var kid) ? kid.GetString() : null;

        private JwtHeaderDocument(JwtDocument document, int algPosition, int kidPosition)
        {
            _document = document;
            _root = document.RootElement;
            _alg = algPosition < 0 ? default : new JwtElement(_document, algPosition);
            _kid = kidPosition < 0 ? default : new JwtElement(_document, kidPosition);
        }

        public JwtElement Alg => _alg;

        internal static bool TryParse(ReadOnlyMemory<byte> utf8Payload, TokenValidationPolicy policy, [NotNullWhen(true)] out JwtHeaderDocument? header, [NotNullWhen(false)] out TokenValidationError? error)
        {
            ReadOnlySpan<byte> utf8JsonSpan = utf8Payload.Span;
            var database = new MetadataDb(utf8Payload.Length);
            int algPosition = -1;
            int kidPosition = -1;

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
                                        algPosition = database.Length;
                                        break;
                                    case JwtHeaderParameters.Kid:
                                        kidPosition = database.Length;
                                        break;
                                }
                            }

                            // Adding 1 to skip the start quote will never overflow
                            Debug.Assert(tokenStart < int.MaxValue);
                            database.Append(JsonTokenType.String, tokenStart + 1, reader.ValueSpan.Length);
                        }
                        else if (tokenType == JsonTokenType.StartObject)
                        {
                            int count = SkipArrayOrObject(ref reader);
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
                                count = SkipArrayOrObject(ref reader);
                            }

                            int index = database.Length;
                            int tokenEnd = (int)reader.TokenStartIndex;
                            database.Append(JsonTokenType.StartArray, tokenStart, tokenEnd - tokenStart + 1);
                            database.SetNumberOfRows(index, count);
                        }
                        else // if (tokenType == JsonTokenType.Number)
                        {
                            Debug.Assert(tokenType >= JsonTokenType.Number && tokenType <= JsonTokenType.Null);
                            database.Append(tokenType, tokenStart, reader.ValueSpan.Length);
                        }
                    }
                }
            }

            Debug.Assert(reader.BytesConsumed == utf8JsonSpan.Length);
            database.TrimExcess();

            header = new JwtHeaderDocument(new JwtDocument(utf8Payload, database, null), algPosition, kidPosition);
            error = null;
            return true;

        Error:
            header = null;
            return false;
        }

        private static int SkipArrayOrObject(ref Utf8JsonReader reader)
        {
            int count = 0;
            int depth = reader.CurrentDepth;
            int depth1 = depth + 1;
            do
            {
                if (depth1 == reader.CurrentDepth)
                {
                    count++;
                }
            }
            while (reader.Read() && depth < reader.CurrentDepth);
            return count;
        }

        //internal static bool TryParse(ReadOnlyMemory<byte> utf8Payload, TokenValidationPolicy policy, [NotNullWhen(true)] out JwtHeaderDocument? header, [NotNullWhen(false)] out TokenValidationError? error)
        //{
        //    ReadOnlySpan<byte> utf8JsonSpan = utf8Payload.Span;
        //    var database = new MetadataDb(utf8Payload.Length);
        //    int arrayItemsCount = 0;
        //    int numberOfRowsForValues = 0;
        //    int algPosition = -1;
        //    int kidPosition = -1;

        //    var reader = new Utf8JsonReader(utf8JsonSpan);

        //    if (reader.Read())
        //    {
        //        JsonTokenType tokenType = reader.TokenType;
        //        if (tokenType == JsonTokenType.StartObject)
        //        {
        //            numberOfRowsForValues++;
        //            int tokenStart = (int)reader.TokenStartIndex;
        //            database.Append(JsonTokenType.StartObject, tokenStart, DbRow.UnknownSize);
        //            int numberOfRowsForMembers = 0;

        //            while (reader.Read())
        //            {
        //                tokenType = reader.TokenType;
        //                tokenStart = (int)reader.TokenStartIndex;

        //                if (tokenType == JsonTokenType.EndObject)
        //                {
        //                    numberOfRowsForMembers++;
        //                    database.SetLength(0, numberOfRowsForMembers);

        //                    int newRowIndex = database.Length;
        //                    database.Append(JsonTokenType.EndObject, tokenStart, reader.ValueSpan.Length);
        //                    database.SetNumberOfRows(0, numberOfRowsForMembers);
        //                    database.SetNumberOfRows(newRowIndex, numberOfRowsForMembers);
        //                    break;
        //                }
        //                else if (tokenType != JsonTokenType.PropertyName)
        //                {
        //                    error = TokenValidationError.MalformedToken();
        //                    goto Error;
        //                }

        //                numberOfRowsForValues++;
        //                numberOfRowsForMembers++;

        //                // Adding 1 to skip the start quote will never overflow
        //                Debug.Assert(tokenStart < int.MaxValue);

        //                database.Append(JsonTokenType.PropertyName, tokenStart + 1, reader.ValueSpan.Length);
        //                ReadOnlySpan<byte> memberName = reader.ValueSpan;

        //                reader.Read();
        //                tokenType = reader.TokenType;
        //                tokenStart = (int)reader.TokenStartIndex;

        //                // Since the input payload is contained within a Span,
        //                // token start index can never be larger than int.MaxValue (i.e. utf8JsonSpan.Length).
        //                Debug.Assert(reader.TokenStartIndex <= int.MaxValue);

        //                if (tokenType == JsonTokenType.String)
        //                {
        //                    if (memberName.Length == 3)
        //                    {
        //                        switch ((JwtHeaderParameters)IntegerMarshal.ReadUInt24(memberName))
        //                        {
        //                            case JwtHeaderParameters.Alg:
        //                                algPosition = database.Length;
        //                                break;
        //                            case JwtHeaderParameters.Kid:
        //                                kidPosition = database.Length;
        //                                break;
        //                        }
        //                    }

        //                    numberOfRowsForValues++;
        //                    numberOfRowsForMembers++;
        //                    // Adding 1 to skip the start quote will never overflow
        //                    Debug.Assert(tokenStart < int.MaxValue);

        //                    database.Append(JsonTokenType.String, tokenStart + 1, reader.ValueSpan.Length);
        //                }
        //                else if (tokenType == JsonTokenType.StartObject)
        //                {
        //                    reader.Skip();
        //                    int tokenEnd = (int)reader.TokenStartIndex;
        //                    numberOfRowsForValues++;
        //                    int rowIndex = database.Length;
        //                    database.Append(JsonTokenType.StartObject, tokenStart, tokenEnd - tokenStart + 1);
        //                    int lenght = numberOfRowsForMembers + 1;
        //                    numberOfRowsForMembers = 0;

        //                    numberOfRowsForValues++;
        //                    numberOfRowsForMembers++;

        //                    int newRowIndex = database.Length;
        //                    database.Append(JsonTokenType.StartObject, tokenStart, reader.ValueSpan.Length);
        //                    database.SetNumberOfRows(rowIndex, numberOfRowsForMembers);
        //                    database.SetNumberOfRows(newRowIndex, numberOfRowsForMembers);

        //                    numberOfRowsForMembers += lenght;
        //                }
        //                else if (tokenType == JsonTokenType.StartArray)
        //                {
        //                    if (memberName.Length == 4
        //                        && (JwtHeaderParameters)IntegerMarshal.ReadUInt32(memberName) == JwtHeaderParameters.Crit
        //                        && !policy.IgnoreCriticalHeader)
        //                    {
        //                        if (!TryCheckCrit(ref reader))
        //                        {
        //                            error = TokenValidationError.MalformedToken("The 'crit' header parameter must be an array of string.");
        //                            goto Error;
        //                        }
        //                    }
        //                    else
        //                    {
        //                        reader.Skip();
        //                    }

        //                    numberOfRowsForMembers++;
        //                    int rowIndex = database.Length;
        //                    int tokenEnd = (int)reader.TokenStartIndex;
        //                    database.Append(JsonTokenType.StartArray, tokenStart, tokenEnd - tokenStart + 1);
        //                    var row = new JwtPayloadDocument.StackRow(arrayItemsCount, numberOfRowsForValues + 1);
        //                    arrayItemsCount = 0;
        //                    numberOfRowsForValues = 0;

        //                    numberOfRowsForValues++;
        //                    numberOfRowsForMembers++;
        //                    database.SetNumberOfRows(rowIndex, numberOfRowsForValues);

        //                    // If the array item count is (e.g.) 12 and the number of rows is (e.g.) 13
        //                    // then the extra row is just this EndArray item, so the array was made up
        //                    // of simple values.
        //                    //
        //                    // If the off-by-one relationship does not hold, then one of the values was
        //                    // more than one row, making it a complex object.
        //                    //
        //                    // This check is similar to tracking the start array and painting it when
        //                    // StartObject or StartArray is encountered, but avoids the mixed state
        //                    // where "UnknownSize" implies "has complex children".
        //                    if (arrayItemsCount + 1 != numberOfRowsForValues)
        //                    {
        //                        database.SetHasComplexChildren(rowIndex);
        //                    }

        //                    int newRowIndex = database.Length;
        //                    tokenStart = (int)reader.TokenStartIndex;
        //                    database.Append(JsonTokenType.StartArray, tokenStart, reader.ValueSpan.Length);
        //                    database.SetNumberOfRows(newRowIndex, numberOfRowsForValues);

        //                    arrayItemsCount = row.SizeOrLength;
        //                    numberOfRowsForValues += row.NumberOfRows;
        //                }
        //                else // if (tokenType == JsonTokenType.Number)
        //                {
        //                    Debug.Assert(tokenType >= JsonTokenType.Number && tokenType <= JsonTokenType.Null);
        //                    numberOfRowsForValues++;
        //                    numberOfRowsForMembers++;

        //                    database.Append(tokenType, tokenStart, reader.ValueSpan.Length);
        //                }
        //            }
        //        }
        //    }

        //    Debug.Assert(reader.BytesConsumed == utf8JsonSpan.Length);
        //    database.TrimExcess();

        //    header = new JwtHeaderDocument(new JwtDocument(utf8Payload, database, null), algPosition, kidPosition);
        //    error = null;
        //    return true;

        //Error:
        //    header = null;
        //    return false;
        //}

        public bool TryGetHeaderParameter(string headerParameterName, out JwtElement value)
        {
            return _document.TryGetProperty(headerParameterName, out value);
        }

        public bool TryGetHeaderParameter(ReadOnlySpan<byte> headerParameterName, out JwtElement value)
        {
            return _document.TryGetProperty(headerParameterName, out value);
        }

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

        public void Dispose()
        {
            _document.Dispose();
        }
    }
}