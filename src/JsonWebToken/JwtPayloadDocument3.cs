using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{

    public sealed partial class JwtPayloadDocument
        : IDisposable
    {
        internal const byte InvalidAudienceFlag = 0x01;
        internal const byte MissingAudienceFlag = 0x02;
        internal const byte InvalidIssuerFlag = 0x04;
        internal const byte MissingIssuerFlag = 0x08;
        internal const byte ExpiredFlag = 0x10;
        internal const byte MissingExpirationFlag = 0x20;
        internal const byte NotYetFlag = 0x40;

        private readonly JwtDocument _document;
        private readonly byte _control;
        private readonly JwtElement _root;

        public byte ValidationControl => _control;
        internal bool InvalidAudience => (_control & InvalidAudienceFlag) == InvalidAudienceFlag;
        internal bool MissingAudience => (_control & MissingAudienceFlag) == MissingAudienceFlag;
        internal bool InvalidIssuer => (_control & InvalidIssuerFlag) == InvalidIssuerFlag;
        internal bool MissingIssuer => (_control & MissingIssuerFlag) == MissingIssuerFlag;
        internal bool MissingExpirationTime => (_control & MissingExpirationFlag) == MissingExpirationFlag;
        internal bool Expired => (_control & ExpiredFlag) == ExpiredFlag;
        internal bool NotYetValid => (_control & NotYetFlag) == NotYetFlag;

        private JwtPayloadDocument(JwtDocument document, byte control)
        {
            _document = document;
            _control = control;
            _root = document.RootElement;
        }

        internal static bool TryParse(ReadOnlyMemory<byte> utf8Payload, TokenValidationPolicy policy, out JwtPayloadDocument? payload, out TokenValidationError? error)
        {
            ReadOnlySpan<byte> utf8JsonSpan = utf8Payload.Span;
            var database = new MetadataDb(utf8Payload.Length);
            byte validationControl = policy.ValidationControl;

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
                                switch ((JwtClaims)IntegerMarshal.ReadUInt24(memberName))
                                {
                                    case JwtClaims.Aud:
                                        CheckStringAudience(ref reader, ref validationControl, policy);
                                        break;

                                    case JwtClaims.Iss:
                                        CheckIssuer(ref reader, ref validationControl, policy);
                                        break;
                                }
                            }

                            // Adding 1 to skip the start quote will never overflow
                            Debug.Assert(tokenStart < int.MaxValue);
                            database.Append(JsonTokenType.String, tokenStart + 1, reader.ValueSpan.Length);
                        }
                        else if (tokenType == JsonTokenType.Number)
                        {
                            if (memberName.Length == 3)
                            {
                                switch ((JwtClaims)IntegerMarshal.ReadUInt24(memberName))
                                {
                                    case JwtClaims.Exp:
                                        if (!TryCheckExpirationTime(ref reader, ref validationControl, policy))
                                        {
                                            error = TokenValidationError.MalformedToken("The claim 'exp' must be an integral number.");
                                            goto Error;
                                        }
                                        break;

                                    case JwtClaims.Nbf:
                                        if (!TryCheckNotBefore(ref reader, ref validationControl, policy))
                                        {
                                            error = TokenValidationError.MalformedToken("The claim 'nbf' must be an integral number.");
                                            goto Error;
                                        }
                                        break;
                                }
                            }

                            database.Append(JsonTokenType.Number, tokenStart, reader.ValueSpan.Length);
                        }
                        else if (tokenType == JsonTokenType.StartObject)
                        {
                            int itemCount = SkipArrayOrObject(ref reader);
                            int tokenEnd = (int)reader.TokenStartIndex;
                            int index = database.Length;
                            database.Append(JsonTokenType.StartObject, tokenStart, tokenEnd - tokenStart + 1);
                            database.SetNumberOfRows(index, itemCount);
                        }
                        else if (tokenType == JsonTokenType.StartArray)
                        {
                            int itemCount;
                            if (memberName.Length == 3 && (JwtClaims)IntegerMarshal.ReadUInt24(memberName) == JwtClaims.Aud)
                            {
                                itemCount = CheckArrayAudience(ref reader, ref validationControl, policy);
                            }
                            else
                            {
                                itemCount = SkipArrayOrObject(ref reader);
                            }

                            int index = database.Length;
                            int tokenEnd = (int)reader.TokenStartIndex;
                            database.Append(JsonTokenType.StartArray, tokenStart, tokenEnd - tokenStart + 1);
                            database.SetNumberOfRows(index, itemCount);
                        }
                        else
                        {
                            Debug.Assert(tokenType >= JsonTokenType.True && tokenType <= JsonTokenType.Null);
                            database.Append(tokenType, tokenStart, reader.ValueSpan.Length);
                        }
                    }
                }
            }

            Debug.Assert(reader.BytesConsumed == utf8JsonSpan.Length);
            database.TrimExcess();

            payload = new JwtPayloadDocument(new JwtDocument(utf8Payload, database, null), validationControl);
            error = null;
            return true;

        Error:
            payload = null;
            return false;
        }

        // internal static bool TryParse(ReadOnlyMemory<byte> utf8Payload, TokenValidationPolicy policy, out JwtPayloadDocument? payload, out TokenValidationError? error)
        //{
        //    ReadOnlySpan<byte> utf8JsonSpan = utf8Payload.Span;
        //    var database = new MetadataDb(utf8Payload.Length);
        //    byte validationControl = policy.ValidationControl;

        //    var reader = new Utf8JsonReader(utf8JsonSpan);
        //    if (reader.Read())
        //    {
        //        JsonTokenType tokenType = reader.TokenType;
        //        if (tokenType == JsonTokenType.StartObject)
        //        {
        //            int tokenStart = (int)reader.TokenStartIndex;
        //            database.Append(JsonTokenType.StartObject, tokenStart, DbRow.UnknownSize);
        //            int numberOfRowsForMembers = 0;
        //            int claimsCount = 0;

        //            while (reader.Read())
        //            {
        //                tokenType = reader.TokenType;
        //                tokenStart = (int)reader.TokenStartIndex;

        //                if (tokenType == JsonTokenType.EndObject)
        //                {
        //                    numberOfRowsForMembers++;
        //                    database.SetLength(0, numberOfRowsForMembers);
        //                    //Debug.Assert(numberOfRowsForMembers == claimsCount);

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

        //                claimsCount++;
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
        //                        switch ((JwtClaims)IntegerMarshal.ReadUInt24(memberName))
        //                        {
        //                            case JwtClaims.Aud:
        //                                CheckStringAudience(ref reader, ref validationControl, policy);
        //                                break;

        //                            case JwtClaims.Iss:
        //                                CheckIssuer(ref reader, ref validationControl, policy);
        //                                break;
        //                        }
        //                    }

        //                    numberOfRowsForMembers++;
        //                    // Adding 1 to skip the start quote will never overflow
        //                    Debug.Assert(tokenStart < int.MaxValue);

        //                    database.Append(JsonTokenType.String, tokenStart + 1, reader.ValueSpan.Length);
        //                }
        //                else if (tokenType == JsonTokenType.Number)
        //                {
        //                    if (memberName.Length == 3)
        //                    {
        //                        switch ((JwtClaims)IntegerMarshal.ReadUInt24(memberName))
        //                        {
        //                            case JwtClaims.Exp:
        //                                if (!TryCheckExpirationTime(ref reader, ref validationControl, policy))
        //                                {
        //                                    error = TokenValidationError.MalformedToken("The claim 'exp' must be an integral number.");
        //                                    goto Error;
        //                                }
        //                                break;

        //                            case JwtClaims.Nbf:
        //                                if (!TryCheckNotBefore(ref reader, ref validationControl, policy))
        //                                {
        //                                    error = TokenValidationError.MalformedToken("The claim 'nbf' must be an integral number.");
        //                                    goto Error;
        //                                }
        //                                break;
        //                        }
        //                    }

        //                    numberOfRowsForMembers++;

        //                    database.Append(JsonTokenType.Number, tokenStart, reader.ValueSpan.Length);
        //                }
        //                else if (tokenType == JsonTokenType.StartObject)
        //                {
        //                    SkipArrayOrObject(ref reader);
        //                    int tokenEnd = (int)reader.TokenStartIndex;
        //                    int rowIndex = database.Length;
        //                    database.Append(JsonTokenType.StartObject, tokenStart, tokenEnd - tokenStart + 1);

        //                    numberOfRowsForMembers++;

        //                    int newRowIndex = database.Length;
        //                    database.Append(JsonTokenType.StartObject, tokenStart, reader.ValueSpan.Length);
        //                    database.SetNumberOfRows(rowIndex, 1);// 1 should be replace by the count of member
        //                    database.SetNumberOfRows(newRowIndex, 1); // 1 should be replace by the count of member
        //                }
        //                else if (tokenType == JsonTokenType.StartArray)
        //                {
        //                    if (memberName.Length == 3 && (JwtClaims)IntegerMarshal.ReadUInt24(memberName) == JwtClaims.Aud)
        //                    {
        //                        CheckArrayAudience(ref reader, ref validationControl, policy);
        //                    }
        //                    else
        //                    {
        //                        SkipArrayOrObject(ref reader);
        //                    }

        //                    numberOfRowsForMembers++;
        //                    int rowIndex = database.Length;
        //                    int tokenEnd = (int)reader.TokenStartIndex;
        //                    database.Append(JsonTokenType.StartArray, tokenStart, tokenEnd - tokenStart + 1);
        //                    int numberOfRowsForValues = 1;

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
        //                    //if (arrayItemsCount + 1 != numberOfRowsForValues)
        //                    //{
        //                    //    database.SetHasComplexChildren(rowIndex);
        //                    //}

        //                    int newRowIndex = database.Length;
        //                    tokenStart = (int)reader.TokenStartIndex;
        //                    database.Append(JsonTokenType.StartArray, tokenStart, reader.ValueSpan.Length);
        //                    database.SetNumberOfRows(newRowIndex, numberOfRowsForValues);
        //                }
        //                else
        //                {
        //                    Debug.Assert(tokenType >= JsonTokenType.True && tokenType <= JsonTokenType.Null);
        //                    numberOfRowsForMembers++;

        //                    database.Append(tokenType, tokenStart, reader.ValueSpan.Length);
        //                }
        //            }
        //        }
        //    }

        //    Debug.Assert(reader.BytesConsumed == utf8JsonSpan.Length);
        //    database.TrimExcess();

        //    payload = new JwtPayloadDocument(new JwtDocument(utf8Payload, database, null), validationControl);
        //    error = null;
        //    return true;

        //Error:
        //    payload = null;
        //    return false;
        //}

        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int SkipArrayOrObject(ref Utf8JsonReader reader)
        {
            int count = 0;
            int depth = reader.CurrentDepth;
            do
            {
                count++;
            }
            while (reader.Read() && depth < reader.CurrentDepth);
            return count;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void CheckIssuer(ref Utf8JsonReader reader, ref byte validationControl, TokenValidationPolicy policy)
        {
            if (policy.RequireIssuer)
            {
                if (reader.ValueTextEquals(policy.RequiredIssuerBinary))
                {
                    validationControl &= unchecked((byte)~TokenValidationPolicy.IssuerFlag);
                }
                else
                {
                    validationControl &= unchecked((byte)~JwtPayload.MissingIssuerFlag);
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool TryCheckExpirationTime(ref Utf8JsonReader reader, ref byte validationControl, TokenValidationPolicy policy)
        {
            if (policy.RequireExpirationTime)
            {
                if (!reader.TryGetInt64(out long exp))
                {
                    return false;
                }

                validationControl &= unchecked((byte)~JwtPayload.MissingExpirationFlag);
                if (exp + policy.ClockSkew >= EpochTime.UtcNow)
                {
                    validationControl &= unchecked((byte)~JwtPayload.ExpiredFlag);
                }
            }

            return true;
        }

        private static bool TryCheckNotBefore(ref Utf8JsonReader reader, ref byte validationControl, TokenValidationPolicy policy)
        {
            if (!reader.TryGetInt64(out long nbf))
            {
                return false;
            }

            // the 'nbf' claim is not common. A 2nd call to EpochTime.UtcNow should be rare.
            if (nbf > EpochTime.UtcNow + policy.ClockSkew
                && (policy.ValidationControl & JwtPayload.ExpiredFlag) == JwtPayload.ExpiredFlag)
            {
                validationControl |= JwtPayload.NotYetFlag;
            }

            return true;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void CheckStringAudience(ref Utf8JsonReader reader, ref byte validationControl, TokenValidationPolicy policy)
        {
            if (policy.RequireAudience)
            {
                validationControl &= unchecked((byte)~JwtPayload.MissingAudienceFlag);
                var audiencesBinary = policy.RequiredAudiencesBinary;
                for (int i = 0; i < audiencesBinary.Length; i++)
                {
                    if (reader.ValueTextEquals(audiencesBinary[i]))
                    {
                        validationControl &= unchecked((byte)~TokenValidationPolicy.AudienceFlag);
                        break;
                    }
                }
            }
        }

        private static int CheckArrayAudience(ref Utf8JsonReader reader, ref byte validationControl, TokenValidationPolicy policy)
        {
            int count = 0;
            if (policy.RequireAudience)
            {
                validationControl &= unchecked((byte)~JwtPayload.MissingAudienceFlag);
                while (reader.Read() && reader.TokenType == JsonTokenType.String)
                {
                    count++;
                    var requiredAudiences = policy.RequiredAudiencesBinary;
                    for (int i = 0; i < requiredAudiences.Length; i++)
                    {
                        if (reader.ValueTextEquals(requiredAudiences[i]))
                        {
                            validationControl &= unchecked((byte)~TokenValidationPolicy.AudienceFlag);
                            while (reader.Read() && reader.TokenType == JsonTokenType.String)
                            {
                                // Just read...
                                count++;
                            }

                            goto Found;
                        }
                    }
                }
            }
            else
            {
                while (reader.Read() && reader.TokenType == JsonTokenType.String)
                {
                    // Just read...
                    count++;
                }
            }

        Found:
            if (reader.TokenType != JsonTokenType.EndArray)
            {
                ThrowHelper.ThrowFormatException_MalformedJson("The 'aud' claim must be an array of string or a string.");
            }

            return count;
        }

        public void Dispose()
        {
            _document.Dispose();
        }

        public bool ContainsKey(string claim)
        {
            return _document.ContainsKey(claim);
        }

        public bool ContainsKey(ReadOnlySpan<byte> claim)
        {
            return _document.ContainsKey(claim);
        }

        public bool TryGetProperty(string claim, out JwtElement value)
        {
            return _document.TryGetProperty(claim, out value);
        }

        public bool TryGetProperty(ReadOnlySpan<byte> claim, out JwtElement value)
        {
            return _document.TryGetProperty(claim, out value);
        }

        // SizeOrLength - offset - 0 - size - 4
        // NumberOfRows - offset - 4 - size - 4
        [StructLayout(LayoutKind.Sequential)]
        internal struct StackRow
        {
            internal const int Size = 8;

            internal int SizeOrLength;
            internal int NumberOfRows;

            internal StackRow(int sizeOrLength = 0, int numberOfRows = -1)
            {
                Debug.Assert(sizeOrLength >= 0);
                Debug.Assert(numberOfRows >= -1);

                SizeOrLength = sizeOrLength;
                NumberOfRows = numberOfRows;
            }
        }

        private struct StackRowStack : IDisposable
        {
            private byte[] _rentedBuffer;
            private int _topOfStack;

            public StackRowStack(int initialSize)
            {
                _rentedBuffer = ArrayPool<byte>.Shared.Rent(initialSize);
                _topOfStack = _rentedBuffer.Length;
            }

            public void Dispose()
            {
                byte[] toReturn = _rentedBuffer;
                _rentedBuffer = null!;
                _topOfStack = 0;

                if (toReturn != null)
                {
                    // The data in this rented buffer only conveys the positions and
                    // lengths of tokens in a document, but no content; so it does not
                    // need to be cleared.
                    ArrayPool<byte>.Shared.Return(toReturn);
                }
            }

            internal void Push(StackRow row)
            {
                if (_topOfStack < StackRow.Size)
                {
                    Enlarge();
                }

                _topOfStack -= StackRow.Size;
                MemoryMarshal.Write(_rentedBuffer.AsSpan(_topOfStack), ref row);
            }

            internal StackRow Pop()
            {
                Debug.Assert(_rentedBuffer != null);
                Debug.Assert(_topOfStack <= _rentedBuffer!.Length - StackRow.Size);

                StackRow row = MemoryMarshal.Read<StackRow>(_rentedBuffer.AsSpan(_topOfStack));
                _topOfStack += StackRow.Size;
                return row;
            }

            private void Enlarge()
            {
                byte[] toReturn = _rentedBuffer;
                _rentedBuffer = ArrayPool<byte>.Shared.Rent(toReturn.Length * 2);

                Buffer.BlockCopy(
                    toReturn,
                    _topOfStack,
                    _rentedBuffer,
                    _rentedBuffer.Length - toReturn.Length + _topOfStack,
                    toReturn.Length - _topOfStack);

                _topOfStack += _rentedBuffer.Length - toReturn.Length;

                // The data in this rented buffer only conveys the positions and
                // lengths of tokens in a document, but no content; so it does not
                // need to be cleared.
                ArrayPool<byte>.Shared.Return(toReturn);
            }
        }
    }

    internal static class JsonConstants
    {
        public const byte OpenBrace = (byte)'{';
        public const byte CloseBrace = (byte)'}';
        public const byte OpenBracket = (byte)'[';
        public const byte CloseBracket = (byte)']';
        public const byte Space = (byte)' ';
        public const byte CarriageReturn = (byte)'\r';
        public const byte LineFeed = (byte)'\n';
        public const byte Tab = (byte)'\t';
        public const byte ListSeparator = (byte)',';
        public const byte KeyValueSeperator = (byte)':';
        public const byte Quote = (byte)'"';
        public const byte BackSlash = (byte)'\\';
        public const byte Slash = (byte)'/';
        public const byte BackSpace = (byte)'\b';
        public const byte FormFeed = (byte)'\f';
        public const byte Asterisk = (byte)'*';
        public const byte Colon = (byte)':';
        public const byte Period = (byte)'.';
        public const byte Plus = (byte)'+';
        public const byte Hyphen = (byte)'-';
        public const byte UtcOffsetToken = (byte)'Z';
        public const byte TimePrefix = (byte)'T';

        public const int StackallocThreshold = 256;

        // In the worst case, an ASCII character represented as a single utf-8 byte could expand 6x when escaped.
        // For example: '+' becomes '\u0043'
        // Escaping surrogate pairs (represented by 3 or 4 utf-8 bytes) would expand to 12 bytes (which is still <= 6x).
        // The same factor applies to utf-16 characters.
        public const int MaxExpansionFactorWhileEscaping = 6;

        // In the worst case, a single UTF-16 character could be expanded to 3 UTF-8 bytes.
        // Only surrogate pairs expand to 4 UTF-8 bytes but that is a transformation of 2 UTF-16 characters goign to 4 UTF-8 bytes (factor of 2).
        // All other UTF-16 characters can be represented by either 1 or 2 UTF-8 bytes.
        public const int MaxExpansionFactorWhileTranscoding = 3;

        public static ReadOnlySpan<byte> NaNValue => new byte[] { (byte)'N', (byte)'a', (byte)'N' };
        public static ReadOnlySpan<byte> PositiveInfinityValue => new byte[] { (byte)'I', (byte)'n', (byte)'f', (byte)'i', (byte)'n', (byte)'i', (byte)'t', (byte)'y' };
        public static ReadOnlySpan<byte> NegativeInfinityValue => new byte[] { (byte)'-', (byte)'I', (byte)'n', (byte)'f', (byte)'i', (byte)'n', (byte)'i', (byte)'t', (byte)'y' };

        // Encoding Helpers
        public const char HighSurrogateStart = '\ud800';
        public const char HighSurrogateEnd = '\udbff';
        public const char LowSurrogateStart = '\udc00';
        public const char LowSurrogateEnd = '\udfff';

        public const int UnicodePlane01StartValue = 0x10000;
        public const int HighSurrogateStartValue = 0xD800;
        public const int HighSurrogateEndValue = 0xDBFF;
        public const int LowSurrogateStartValue = 0xDC00;
        public const int LowSurrogateEndValue = 0xDFFF;
        public const int BitShiftBy10 = 0x400;
    }


    internal static partial class JsonReaderHelper
    {
        public static string TranscodeHelper(ReadOnlySpan<byte> utf8Unescaped)
        {
            try
            {
                return Utf8.GetString(utf8Unescaped);
            }
            catch (DecoderFallbackException ex)
            {
                // We want to be consistent with the exception being thrown
                // so the user only has to catch a single exception.
                // Since we already throw InvalidOperationException for mismatch token type,
                // and while unescaping, using that exception for failure to decode invalid UTF-8 bytes as well.
                // Therefore, wrapping the DecoderFallbackException around an InvalidOperationException.
                //   throw ThrowHelper.GetInvalidOperationException_ReadInvalidUTF8(ex);
                throw new InvalidOperationException("Invalid UTF8", ex);
            }
        }


        public static (int, int) CountNewLines(ReadOnlySpan<byte> data)
        {
            int lastLineFeedIndex = -1;
            int newLines = 0;
            for (int i = 0; i < data.Length; i++)
            {
                if (data[i] == JsonConstants.LineFeed)
                {
                    lastLineFeedIndex = i;
                    newLines++;
                }
            }
            return (newLines, lastLineFeedIndex);
        }

        internal static JsonValueKind ToValueKind(this JsonTokenType tokenType)
        {
            switch (tokenType)
            {
                case JsonTokenType.None:
                    return JsonValueKind.Undefined;
                case JsonTokenType.StartArray:
                    return JsonValueKind.Array;
                case JsonTokenType.StartObject:
                    return JsonValueKind.Object;
                case JsonTokenType.String:
                case JsonTokenType.Number:
                case JsonTokenType.True:
                case JsonTokenType.False:
                case JsonTokenType.Null:
                    // This is the offset between the set of literals within JsonValueType and JsonTokenType
                    // Essentially: JsonTokenType.Null - JsonValueType.Null
                    return (JsonValueKind)((byte)tokenType - 4);
                default:
                    Debug.Fail($"No mapping for token type {tokenType}");
                    return JsonValueKind.Undefined;
            }
        }

        // Returns true if the TokenType is a primitive "value", i.e. String, Number, True, False, and Null
        // Otherwise, return false.
        public static bool IsTokenTypePrimitive(JsonTokenType tokenType) =>
            (tokenType - JsonTokenType.String) <= (JsonTokenType.Null - JsonTokenType.String);

        //// A hex digit is valid if it is in the range: [0..9] | [A..F] | [a..f]
        //// Otherwise, return false.
        //public static bool IsHexDigit(byte nextByte) => HexConverter.IsHexChar(nextByte);

        // https://tools.ietf.org/html/rfc8259
        // Does the span contain '"', '\',  or any control characters (i.e. 0 to 31)
        // IndexOfAny(34, 92, < 32)
        // Borrowed and modified from SpanHelpers.Byte:
        // https://github.com/dotnet/corefx/blob/fc169cddedb6820aaabbdb8b7bece2a3df0fd1a5/src/Common/src/CoreLib/System/SpanHelpers.Byte.cs#L473-L604
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int IndexOfQuoteOrAnyControlOrBackSlash(this ReadOnlySpan<byte> span)
        {
            return IndexOfOrLessThan(
                    ref MemoryMarshal.GetReference(span),
                    JsonConstants.Quote,
                    JsonConstants.BackSlash,
                    lessThan: 32,   // Space ' '
                    span.Length);
        }

        private static unsafe int IndexOfOrLessThan(ref byte searchSpace, byte value0, byte value1, byte lessThan, int length)
        {
            Debug.Assert(length >= 0);

            uint uValue0 = value0; // Use uint for comparisons to avoid unnecessary 8->32 extensions
            uint uValue1 = value1; // Use uint for comparisons to avoid unnecessary 8->32 extensions
            uint uLessThan = lessThan; // Use uint for comparisons to avoid unnecessary 8->32 extensions
            IntPtr index = (IntPtr)0; // Use IntPtr for arithmetic to avoid unnecessary 64->32->64 truncations
            IntPtr nLength = (IntPtr)length;

            if (Vector.IsHardwareAccelerated && length >= Vector<byte>.Count * 2)
            {
                int unaligned = (int)Unsafe.AsPointer(ref searchSpace) & (Vector<byte>.Count - 1);
                nLength = (IntPtr)((Vector<byte>.Count - unaligned) & (Vector<byte>.Count - 1));
            }
        SequentialScan:
            uint lookUp;
            while ((byte*)nLength >= (byte*)8)
            {
                nLength -= 8;

                lookUp = Unsafe.AddByteOffset(ref searchSpace, index);
                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
                    goto Found;
                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 1);
                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
                    goto Found1;
                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 2);
                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
                    goto Found2;
                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 3);
                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
                    goto Found3;
                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 4);
                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
                    goto Found4;
                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 5);
                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
                    goto Found5;
                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 6);
                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
                    goto Found6;
                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 7);
                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
                    goto Found7;

                index += 8;
            }

            if ((byte*)nLength >= (byte*)4)
            {
                nLength -= 4;

                lookUp = Unsafe.AddByteOffset(ref searchSpace, index);
                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
                    goto Found;
                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 1);
                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
                    goto Found1;
                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 2);
                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
                    goto Found2;
                lookUp = Unsafe.AddByteOffset(ref searchSpace, index + 3);
                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
                    goto Found3;

                index += 4;
            }

            while ((byte*)nLength > (byte*)0)
            {
                nLength -= 1;

                lookUp = Unsafe.AddByteOffset(ref searchSpace, index);
                if (uValue0 == lookUp || uValue1 == lookUp || uLessThan > lookUp)
                    goto Found;

                index += 1;
            }

            if (Vector.IsHardwareAccelerated && ((int)(byte*)index < length))
            {
                nLength = (IntPtr)((length - (int)(byte*)index) & ~(Vector<byte>.Count - 1));

                // Get comparison Vector
                Vector<byte> values0 = new Vector<byte>(value0);
                Vector<byte> values1 = new Vector<byte>(value1);
                Vector<byte> valuesLessThan = new Vector<byte>(lessThan);

                while ((byte*)nLength > (byte*)index)
                {
                    Vector<byte> vData = Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref searchSpace, index));

                    var vMatches = Vector.BitwiseOr(
                                    Vector.BitwiseOr(
                                        Vector.Equals(vData, values0),
                                        Vector.Equals(vData, values1)),
                                    Vector.LessThan(vData, valuesLessThan));

                    if (Vector<byte>.Zero.Equals(vMatches))
                    {
                        index += Vector<byte>.Count;
                        continue;
                    }
                    // Find offset of first match
                    return (int)(byte*)index + LocateFirstFoundByte(vMatches);
                }

                if ((int)(byte*)index < length)
                {
                    nLength = (IntPtr)(length - (int)(byte*)index);
                    goto SequentialScan;
                }
            }
            return -1;
        Found: // Workaround for https://github.com/dotnet/runtime/issues/8795
            return (int)(byte*)index;
        Found1:
            return (int)(byte*)(index + 1);
        Found2:
            return (int)(byte*)(index + 2);
        Found3:
            return (int)(byte*)(index + 3);
        Found4:
            return (int)(byte*)(index + 4);
        Found5:
            return (int)(byte*)(index + 5);
        Found6:
            return (int)(byte*)(index + 6);
        Found7:
            return (int)(byte*)(index + 7);
        }

        // Vector sub-search adapted from https://github.com/aspnet/KestrelHttpServer/pull/1138
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int LocateFirstFoundByte(Vector<byte> match)
        {
            var vector64 = Vector.AsVectorUInt64(match);
            ulong candidate = 0;
            int i = 0;
            // Pattern unrolled by jit https://github.com/dotnet/coreclr/pull/8001
            for (; i < Vector<ulong>.Count; i++)
            {
                candidate = vector64[i];
                if (candidate != 0)
                {
                    break;
                }
            }

            // Single LEA instruction with jitted const (using function result)
            return i * 8 + LocateFirstFoundByte(candidate);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int LocateFirstFoundByte(ulong match)
        {
            // Flag least significant power of two bit
            var powerOfTwoFlag = match ^ (match - 1);
            // Shift all powers of two into the high byte and extract
            return (int)((powerOfTwoFlag * XorPowerOfTwoToHighByte) >> 57);
        }

        private const ulong XorPowerOfTwoToHighByte = (0x07ul |
                                               0x06ul << 8 |
                                               0x05ul << 16 |
                                               0x04ul << 24 |
                                               0x03ul << 32 |
                                               0x02ul << 40 |
                                               0x01ul << 48) + 1;

        public static bool TryGetFloatingPointConstant(ReadOnlySpan<byte> span, out double value)
        {
            if (span.Length == 3)
            {
                if (span.SequenceEqual(JsonConstants.NaNValue))
                {
                    value = double.NaN;
                    return true;
                }
            }
            else if (span.Length == 8)
            {
                if (span.SequenceEqual(JsonConstants.PositiveInfinityValue))
                {
                    value = double.PositiveInfinity;
                    return true;
                }
            }
            else if (span.Length == 9)
            {
                if (span.SequenceEqual(JsonConstants.NegativeInfinityValue))
                {
                    value = double.NegativeInfinity;
                    return true;
                }
            }

            value = 0;
            return false;
        }

        internal static int GetUtf8FromText(ReadOnlySpan<char> text, Span<byte> dest)
        {
            try
            {
                return Utf8.GetBytes(text, dest);
            }
            catch (EncoderFallbackException ex)
            {
                // We want to be consistent with the exception being thrown
                // so the user only has to catch a single exception.
                // Since we already throw ArgumentException when validating other arguments,
                // using that exception for failure to encode invalid UTF-16 chars as well.
                // Therefore, wrapping the EncoderFallbackException around an ArgumentException.
                //throw  ThrowHelper.GetArgumentException_ReadInvalidUTF16(ex);
                throw new InvalidOperationException("Invalid UTF16", ex);
            }
        }
        internal static void Unescape(ReadOnlySpan<byte> source, Span<byte> destination, int idx, out int written)
        {
            Debug.Assert(idx >= 0 && idx < source.Length);
            Debug.Assert(source[idx] == JsonConstants.BackSlash);
            Debug.Assert(destination.Length >= source.Length);

            source.Slice(0, idx).CopyTo(destination);
            written = idx;

            for (; idx < source.Length; idx++)
            {
                byte currentByte = source[idx];
                if (currentByte == JsonConstants.BackSlash)
                {
                    idx++;
                    currentByte = source[idx];

                    if (currentByte == JsonConstants.Quote)
                    {
                        destination[written++] = JsonConstants.Quote;
                    }
                    else if (currentByte == 'n')
                    {
                        destination[written++] = JsonConstants.LineFeed;
                    }
                    else if (currentByte == 'r')
                    {
                        destination[written++] = JsonConstants.CarriageReturn;
                    }
                    else if (currentByte == JsonConstants.BackSlash)
                    {
                        destination[written++] = JsonConstants.BackSlash;
                    }
                    else if (currentByte == JsonConstants.Slash)
                    {
                        destination[written++] = JsonConstants.Slash;
                    }
                    else if (currentByte == 't')
                    {
                        destination[written++] = JsonConstants.Tab;
                    }
                    else if (currentByte == 'b')
                    {
                        destination[written++] = JsonConstants.BackSpace;
                    }
                    else if (currentByte == 'f')
                    {
                        destination[written++] = JsonConstants.FormFeed;
                    }
                    else if (currentByte == 'u')
                    {
                        // The source is known to be valid JSON, and hence if we see a \u, it is guaranteed to have 4 hex digits following it
                        // Otherwise, the Utf8JsonReader would have alreayd thrown an exception.
                        Debug.Assert(source.Length >= idx + 5);

                        bool result = Utf8Parser.TryParse(source.Slice(idx + 1, 4), out int scalar, out int bytesConsumed, 'x');
                        Debug.Assert(result);
                        Debug.Assert(bytesConsumed == 4);
                        idx += bytesConsumed;     // The loop iteration will increment idx past the last hex digit

                        if (IsInRangeInclusive((uint)scalar, JsonConstants.HighSurrogateStartValue, JsonConstants.LowSurrogateEndValue))
                        {
                            // The first hex value cannot be a low surrogate.
                            if (scalar >= JsonConstants.LowSurrogateStartValue)
                            {
                                //ThrowHelper.ThrowInvalidOperationException_ReadInvalidUTF16(scalar);
                                throw new InvalidOperationException("Invalid UTF16");

                            }

                            Debug.Assert(IsInRangeInclusive((uint)scalar, JsonConstants.HighSurrogateStartValue, JsonConstants.HighSurrogateEndValue));

                            idx += 3;   // Skip the last hex digit and the next \u

                            // We must have a low surrogate following a high surrogate.
                            if (source.Length < idx + 4 || source[idx - 2] != '\\' || source[idx - 1] != 'u')
                            {
                                throw new InvalidOperationException("Invalid UTF16");
                                //ThrowHelper.ThrowInvalidOperationException_ReadInvalidUTF16();
                            }

                            // The source is known to be valid JSON, and hence if we see a \u, it is guaranteed to have 4 hex digits following it
                            // Otherwise, the Utf8JsonReader would have alreayd thrown an exception.
                            result = Utf8Parser.TryParse(source.Slice(idx, 4), out int lowSurrogate, out bytesConsumed, 'x');
                            Debug.Assert(result);
                            Debug.Assert(bytesConsumed == 4);

                            // If the first hex value is a high surrogate, the next one must be a low surrogate.
                            if (!IsInRangeInclusive((uint)lowSurrogate, JsonConstants.LowSurrogateStartValue, JsonConstants.LowSurrogateEndValue))
                            {
                                //ThrowHelper.ThrowInvalidOperationException_ReadInvalidUTF16(lowSurrogate);
                                throw new InvalidOperationException("Invalid UTF16");
                            }

                            idx += bytesConsumed - 1;  // The loop iteration will increment idx past the last hex digit

                            // To find the unicode scalar:
                            // (0x400 * (High surrogate - 0xD800)) + Low surrogate - 0xDC00 + 0x10000
                            scalar = (JsonConstants.BitShiftBy10 * (scalar - JsonConstants.HighSurrogateStartValue))
                                + (lowSurrogate - JsonConstants.LowSurrogateStartValue)
                                + JsonConstants.UnicodePlane01StartValue;
                        }

#if SUPPORT_SIMD
                        var rune = new Rune(scalar);
                        int bytesWritten = rune.EncodeToUtf8(destination.Slice(written));
#else
                        EncodeToUtf8Bytes((uint)scalar, destination.Slice(written), out int bytesWritten);
#endif
                        Debug.Assert(bytesWritten <= 4);
                        written += bytesWritten;
                    }
                }
                else
                {
                    destination[written++] = currentByte;
                }
            }
        }

        /// <summary>
        /// Returns <see langword="true"/> if <paramref name="value"/> is between
        /// <paramref name="lowerBound"/> and <paramref name="upperBound"/>, inclusive.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsInRangeInclusive(uint value, uint lowerBound, uint upperBound)
            => (value - lowerBound) <= (upperBound - lowerBound);

        /// <summary>
        /// Returns <see langword="true"/> if <paramref name="value"/> is between
        /// <paramref name="lowerBound"/> and <paramref name="upperBound"/>, inclusive.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsInRangeInclusive(int value, int lowerBound, int upperBound)
            => (uint)(value - lowerBound) <= (uint)(upperBound - lowerBound);

        /// <summary>
        /// Returns <see langword="true"/> if <paramref name="value"/> is between
        /// <paramref name="lowerBound"/> and <paramref name="upperBound"/>, inclusive.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsInRangeInclusive(long value, long lowerBound, long upperBound)
            => (ulong)(value - lowerBound) <= (ulong)(upperBound - lowerBound);

        /// <summary>
        /// Returns <see langword="true"/> if <paramref name="value"/> is between
        /// <paramref name="lowerBound"/> and <paramref name="upperBound"/>, inclusive.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsInRangeInclusive(JsonTokenType value, JsonTokenType lowerBound, JsonTokenType upperBound)
            => (value - lowerBound) <= (upperBound - lowerBound);

        public static bool UnescapeAndCompare(ReadOnlySpan<byte> utf8Source, ReadOnlySpan<byte> other)
        {
            Debug.Assert(utf8Source.Length >= other.Length && utf8Source.Length / JsonConstants.MaxExpansionFactorWhileEscaping <= other.Length);

            byte[]? unescapedArray = null;

            Span<byte> utf8Unescaped = utf8Source.Length <= JsonConstants.StackallocThreshold ?
                stackalloc byte[utf8Source.Length] :
                (unescapedArray = ArrayPool<byte>.Shared.Rent(utf8Source.Length));

            Unescape(utf8Source, utf8Unescaped, 0, out int written);
            Debug.Assert(written > 0);

            utf8Unescaped = utf8Unescaped.Slice(0, written);
            Debug.Assert(!utf8Unescaped.IsEmpty);

            bool result = other.SequenceEqual(utf8Unescaped);

            if (unescapedArray != null)
            {
                utf8Unescaped.Clear();
                ArrayPool<byte>.Shared.Return(unescapedArray);
            }

            return result;
        }

        // TODO: Similar to escaping, replace the unescaping logic with publicly shipping APIs from https://github.com/dotnet/runtime/issues/27919
        public static string GetUnescapedString(ReadOnlySpan<byte> utf8Source, int idx)
        {
            // The escaped name is always >= than the unescaped, so it is safe to use escaped name for the buffer length.
            int length = utf8Source.Length;
            byte[]? pooledName = null;

            Span<byte> utf8Unescaped = length <= JsonConstants.StackallocThreshold ?
                stackalloc byte[length] :
                (pooledName = ArrayPool<byte>.Shared.Rent(length));

            Unescape(utf8Source, utf8Unescaped, idx, out int written);
            Debug.Assert(written > 0);

            utf8Unescaped = utf8Unescaped.Slice(0, written);
            Debug.Assert(!utf8Unescaped.IsEmpty);

            string utf8String = TranscodeHelper(utf8Unescaped);

            if (pooledName != null)
            {
                utf8Unescaped.Clear();
                ArrayPool<byte>.Shared.Return(pooledName);
            }

            return utf8String;
        }

#if !SUPPORT_SIMD
        /// <summary>
        /// Copies the UTF-8 code unit representation of this scalar to an output buffer.
        /// The buffer must be large enough to hold the required number of <see cref="byte"/>s.
        /// </summary>
        private static void EncodeToUtf8Bytes(uint scalar, Span<byte> utf8Destination, out int bytesWritten)
        {
            Debug.Assert(IsValidUnicodeScalar(scalar));
            Debug.Assert(utf8Destination.Length >= 4);

            if (scalar < 0x80U)
            {
                // Single UTF-8 code unit
                utf8Destination[0] = (byte)scalar;
                bytesWritten = 1;
            }
            else if (scalar < 0x800U)
            {
                // Two UTF-8 code units
                utf8Destination[0] = (byte)(0xC0U | (scalar >> 6));
                utf8Destination[1] = (byte)(0x80U | (scalar & 0x3FU));
                bytesWritten = 2;
            }
            else if (scalar < 0x10000U)
            {
                // Three UTF-8 code units
                utf8Destination[0] = (byte)(0xE0U | (scalar >> 12));
                utf8Destination[1] = (byte)(0x80U | ((scalar >> 6) & 0x3FU));
                utf8Destination[2] = (byte)(0x80U | (scalar & 0x3FU));
                bytesWritten = 3;
            }
            else
            {
                // Four UTF-8 code units
                utf8Destination[0] = (byte)(0xF0U | (scalar >> 18));
                utf8Destination[1] = (byte)(0x80U | ((scalar >> 12) & 0x3FU));
                utf8Destination[2] = (byte)(0x80U | ((scalar >> 6) & 0x3FU));
                utf8Destination[3] = (byte)(0x80U | (scalar & 0x3FU));
                bytesWritten = 4;
            }
        }

        /// <summary>
        /// Returns <see langword="true"/> if <paramref name="value"/> is a valid Unicode scalar
        /// value, i.e., is in [ U+0000..U+D7FF ], inclusive; or [ U+E000..U+10FFFF ], inclusive.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsValidUnicodeScalar(uint value)
        {
            // By XORing the incoming value with 0xD800, surrogate code points
            // are moved to the range [ U+0000..U+07FF ], and all valid scalar
            // values are clustered into the single range [ U+0800..U+10FFFF ],
            // which allows performing a single fast range check.

            return IsInRangeInclusive(value ^ 0xD800U, 0x800U, 0x10FFFFU);
        }
#endif

        // TODO: Replace this with publicly shipping implementation: https://github.com/dotnet/runtime/issues/28204
        /// <summary>
        /// Converts a span containing a sequence of UTF-16 bytes into UTF-8 bytes.
        ///
        /// This method will consume as many of the input bytes as possible.
        ///
        /// On successful exit, the entire input was consumed and encoded successfully. In this case, <paramref name="bytesConsumed"/> will be
        /// equal to the length of the <paramref name="utf16Source"/> and <paramref name="bytesWritten"/> will equal the total number of bytes written to
        /// the <paramref name="utf8Destination"/>.
        /// </summary>
        /// <param name="utf16Source">A span containing a sequence of UTF-16 bytes.</param>
        /// <param name="utf8Destination">A span to write the UTF-8 bytes into.</param>
        /// <param name="bytesConsumed">On exit, contains the number of bytes that were consumed from the <paramref name="utf16Source"/>.</param>
        /// <param name="bytesWritten">On exit, contains the number of bytes written to <paramref name="utf8Destination"/></param>
        /// <returns>A <see cref="OperationStatus"/> value representing the state of the conversion.</returns>
        public static unsafe OperationStatus ToUtf8(ReadOnlySpan<byte> utf16Source, Span<byte> utf8Destination, out int bytesConsumed, out int bytesWritten)
        {
            //
            //
            // KEEP THIS IMPLEMENTATION IN SYNC WITH https://github.com/dotnet/coreclr/blob/master/src/System.Private.CoreLib/shared/System/Text/UTF8Encoding.cs#L841
            //
            //
            fixed (byte* chars = &MemoryMarshal.GetReference(utf16Source))
            fixed (byte* bytes = &MemoryMarshal.GetReference(utf8Destination))
            {
                char* pSrc = (char*)chars;
                byte* pTarget = bytes;

                char* pEnd = (char*)(chars + utf16Source.Length);
                byte* pAllocatedBufferEnd = pTarget + utf8Destination.Length;

                // assume that JIT will enregister pSrc, pTarget and ch

                // Entering the fast encoding loop incurs some overhead that does not get amortized for small
                // number of characters, and the slow encoding loop typically ends up running for the last few
                // characters anyway since the fast encoding loop needs 5 characters on input at least.
                // Thus don't use the fast decoding loop at all if we don't have enough characters. The threashold
                // was choosen based on performance testing.
                // Note that if we don't have enough bytes, pStop will prevent us from entering the fast loop.
                while (pEnd - pSrc > 13)
                {
                    // we need at least 1 byte per character, but Convert might allow us to convert
                    // only part of the input, so try as much as we can.  Reduce charCount if necessary
                    int available = Math.Min(PtrDiff(pEnd, pSrc), PtrDiff(pAllocatedBufferEnd, pTarget));

                    // FASTLOOP:
                    // - optimistic range checks
                    // - fallbacks to the slow loop for all special cases, exception throwing, etc.

                    // To compute the upper bound, assume that all characters are ASCII characters at this point,
                    //  the boundary will be decreased for every non-ASCII character we encounter
                    // Also, we need 5 chars reserve for the unrolled ansi decoding loop and for decoding of surrogates
                    // If there aren't enough bytes for the output, then pStop will be <= pSrc and will bypass the loop.
                    char* pStop = pSrc + available - 5;
                    if (pSrc >= pStop)
                        break;

                    do
                    {
                        int ch = *pSrc;
                        pSrc++;

                        if (ch > 0x7F)
                        {
                            goto LongCode;
                        }
                        *pTarget = (byte)ch;
                        pTarget++;

                        // get pSrc aligned
                        if ((unchecked((int)pSrc) & 0x2) != 0)
                        {
                            ch = *pSrc;
                            pSrc++;
                            if (ch > 0x7F)
                            {
                                goto LongCode;
                            }
                            *pTarget = (byte)ch;
                            pTarget++;
                        }

                        // Run 4 characters at a time!
                        while (pSrc < pStop)
                        {
                            ch = *(int*)pSrc;
                            int chc = *(int*)(pSrc + 2);
                            if (((ch | chc) & unchecked((int)0xFF80FF80)) != 0)
                            {
                                goto LongCodeWithMask;
                            }

                            // Unfortunately, this is endianess sensitive
#if BIGENDIAN
                                *pTarget = (byte)(ch >> 16);
                                *(pTarget + 1) = (byte)ch;
                                pSrc += 4;
                                *(pTarget + 2) = (byte)(chc >> 16);
                                *(pTarget + 3) = (byte)chc;
                                pTarget += 4;
#else // BIGENDIAN
                            *pTarget = (byte)ch;
                            *(pTarget + 1) = (byte)(ch >> 16);
                            pSrc += 4;
                            *(pTarget + 2) = (byte)chc;
                            *(pTarget + 3) = (byte)(chc >> 16);
                            pTarget += 4;
#endif // BIGENDIAN
                        }
                        continue;

                    LongCodeWithMask:
#if BIGENDIAN
                            // be careful about the sign extension
                            ch = (int)(((uint)ch) >> 16);
#else // BIGENDIAN
                        ch = (char)ch;
#endif // BIGENDIAN
                        pSrc++;

                        if (ch > 0x7F)
                        {
                            goto LongCode;
                        }
                        *pTarget = (byte)ch;
                        pTarget++;
                        continue;

                    LongCode:
                        // use separate helper variables for slow and fast loop so that the jit optimizations
                        // won't get confused about the variable lifetimes
                        int chd;
                        if (ch <= 0x7FF)
                        {
                            // 2 byte encoding
                            chd = unchecked((sbyte)0xC0) | (ch >> 6);
                        }
                        else
                        {
                            // if (!IsLowSurrogate(ch) && !IsHighSurrogate(ch))
                            if (!IsInRangeInclusive(ch, JsonConstants.HighSurrogateStart, JsonConstants.LowSurrogateEnd))
                            {
                                // 3 byte encoding
                                chd = unchecked((sbyte)0xE0) | (ch >> 12);
                            }
                            else
                            {
                                // 4 byte encoding - high surrogate + low surrogate
                                // if (!IsHighSurrogate(ch))
                                if (ch > JsonConstants.HighSurrogateEnd)
                                {
                                    // low without high -> bad
                                    goto InvalidData;
                                }

                                chd = *pSrc;

                                // if (!IsLowSurrogate(chd)) {
                                if (!IsInRangeInclusive(chd, JsonConstants.LowSurrogateStart, JsonConstants.LowSurrogateEnd))
                                {
                                    // high not followed by low -> bad
                                    goto InvalidData;
                                }

                                pSrc++;

                                ch = chd + (ch << 10) +
                                    (0x10000
                                    - JsonConstants.LowSurrogateStart
                                    - (JsonConstants.HighSurrogateStart << 10));

                                *pTarget = (byte)(unchecked((sbyte)0xF0) | (ch >> 18));
                                // pStop - this byte is compensated by the second surrogate character
                                // 2 input chars require 4 output bytes.  2 have been anticipated already
                                // and 2 more will be accounted for by the 2 pStop-- calls below.
                                pTarget++;

                                chd = unchecked((sbyte)0x80) | (ch >> 12) & 0x3F;
                            }
                            *pTarget = (byte)chd;
                            pStop--;                    // 3 byte sequence for 1 char, so need pStop-- and the one below too.
                            pTarget++;

                            chd = unchecked((sbyte)0x80) | (ch >> 6) & 0x3F;
                        }
                        *pTarget = (byte)chd;
                        pStop--;                        // 2 byte sequence for 1 char so need pStop--.

                        *(pTarget + 1) = (byte)(unchecked((sbyte)0x80) | ch & 0x3F);
                        // pStop - this byte is already included

                        pTarget += 2;
                    }
                    while (pSrc < pStop);

                    Debug.Assert(pTarget <= pAllocatedBufferEnd, "[UTF8Encoding.GetBytes]pTarget <= pAllocatedBufferEnd");
                }

                while (pSrc < pEnd)
                {
                    // SLOWLOOP: does all range checks, handles all special cases, but it is slow

                    // read next char. The JIT optimization seems to be getting confused when
                    // compiling "ch = *pSrc++;", so rather use "ch = *pSrc; pSrc++;" instead
                    int ch = *pSrc;
                    pSrc++;

                    if (ch <= 0x7F)
                    {
                        if (pAllocatedBufferEnd - pTarget <= 0)
                            goto DestinationFull;

                        *pTarget = (byte)ch;
                        pTarget++;
                        continue;
                    }

                    int chd;
                    if (ch <= 0x7FF)
                    {
                        if (pAllocatedBufferEnd - pTarget <= 1)
                            goto DestinationFull;

                        // 2 byte encoding
                        chd = unchecked((sbyte)0xC0) | (ch >> 6);
                    }
                    else
                    {
                        // if (!IsLowSurrogate(ch) && !IsHighSurrogate(ch))
                        if (!IsInRangeInclusive(ch, JsonConstants.HighSurrogateStart, JsonConstants.LowSurrogateEnd))
                        {
                            if (pAllocatedBufferEnd - pTarget <= 2)
                                goto DestinationFull;

                            // 3 byte encoding
                            chd = unchecked((sbyte)0xE0) | (ch >> 12);
                        }
                        else
                        {
                            if (pAllocatedBufferEnd - pTarget <= 3)
                                goto DestinationFull;

                            // 4 byte encoding - high surrogate + low surrogate
                            // if (!IsHighSurrogate(ch))
                            if (ch > JsonConstants.HighSurrogateEnd)
                            {
                                // low without high -> bad
                                goto InvalidData;
                            }

                            if (pSrc >= pEnd)
                                goto NeedMoreData;

                            chd = *pSrc;

                            // if (!IsLowSurrogate(chd)) {
                            if (!IsInRangeInclusive(chd, JsonConstants.LowSurrogateStart, JsonConstants.LowSurrogateEnd))
                            {
                                // high not followed by low -> bad
                                goto InvalidData;
                            }

                            pSrc++;

                            ch = chd + (ch << 10) +
                                (0x10000
                                - JsonConstants.LowSurrogateStart
                                - (JsonConstants.HighSurrogateStart << 10));

                            *pTarget = (byte)(unchecked((sbyte)0xF0) | (ch >> 18));
                            pTarget++;

                            chd = unchecked((sbyte)0x80) | (ch >> 12) & 0x3F;
                        }
                        *pTarget = (byte)chd;
                        pTarget++;

                        chd = unchecked((sbyte)0x80) | (ch >> 6) & 0x3F;
                    }

                    *pTarget = (byte)chd;
                    *(pTarget + 1) = (byte)(unchecked((sbyte)0x80) | ch & 0x3F);

                    pTarget += 2;
                }

                bytesConsumed = (int)((byte*)pSrc - chars);
                bytesWritten = (int)(pTarget - bytes);
                return OperationStatus.Done;

            InvalidData:
                bytesConsumed = (int)((byte*)(pSrc - 1) - chars);
                bytesWritten = (int)(pTarget - bytes);
                return OperationStatus.InvalidData;

            DestinationFull:
                bytesConsumed = (int)((byte*)(pSrc - 1) - chars);
                bytesWritten = (int)(pTarget - bytes);
                return OperationStatus.DestinationTooSmall;

            NeedMoreData:
                bytesConsumed = (int)((byte*)(pSrc - 1) - chars);
                bytesWritten = (int)(pTarget - bytes);
                return OperationStatus.NeedMoreData;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe int PtrDiff(char* a, char* b)
        {
            return (int)(((uint)((byte*)a - (byte*)b)) >> 1);
        }

        // byte* flavor just for parity
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe int PtrDiff(byte* a, byte* b)
        {
            return (int)(a - b);
        }
    }

    public partial struct JwtElement
    {
        /// <summary>
        ///   An enumerable and enumerator for the properties of a JSON object.
        /// </summary>
        [DebuggerDisplay("{Current,nq}")]
        public struct ObjectEnumerator : IEnumerable<JwtMember>, IEnumerator<JwtMember>
        {
            private readonly JwtElement _target;
            private int _curIdx;
            private readonly int _endIdxOrVersion;

            internal ObjectEnumerator(JwtElement target)
            {
                _target = target;
                _curIdx = -1;

                Debug.Assert(target.TokenType == JsonTokenType.StartObject);
                _endIdxOrVersion = target._parent.GetEndIndex(_target._idx, includeEndElement: false);
            }

            /// <inheritdoc />
            public JwtMember Current
            {
                get
                {
                    if (_curIdx < 0)
                    {
                        return default;
                    }

                    return new JwtMember(new JwtElement(_target._parent, _curIdx));
                }
            }

            /// <summary>
            ///   Returns an enumerator that iterates the properties of an object.
            /// </summary>
            /// <returns>
            ///   An <see cref="ObjectEnumerator"/> value that can be used to iterate
            ///   through the object.
            /// </returns>
            /// <remarks>
            ///   The enumerator will enumerate the properties in the order they are
            ///   declared, and when an object has multiple definitions of a single
            ///   property they will all individually be returned (each in the order
            ///   they appear in the content).
            /// </remarks>
            public ObjectEnumerator GetEnumerator()
            {
                ObjectEnumerator ator = this;
                ator._curIdx = -1;
                return ator;
            }

            /// <inheritdoc />
            IEnumerator<JwtMember> IEnumerable<JwtMember>.GetEnumerator() => GetEnumerator();

            /// <inheritdoc />
            public void Dispose()
            {
                _curIdx = _endIdxOrVersion;
            }

            /// <inheritdoc />
            public void Reset()
            {
                _curIdx = -1;
            }

            /// <inheritdoc />
            object System.Collections.IEnumerator.Current => Current;

            /// <inheritdoc />
            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

            /// <inheritdoc />
            public bool MoveNext()
            {
                if (_curIdx >= _endIdxOrVersion)
                {
                    return false;
                }

                if (_curIdx < 0)
                {
                    _curIdx = _target._idx + DbRow.Size;
                }
                else
                {
                    _curIdx = _target._parent.GetEndIndex(_curIdx, includeEndElement: true);
                }

                // _curIdx is now pointing at a property name, move one more to get the value
                _curIdx += DbRow.Size;

                return _curIdx < _endIdxOrVersion;
            }
        }

        /// <summary>
        ///   An enumerable and enumerator for the contents of a JSON array.
        /// </summary>
        [DebuggerDisplay("{Current,nq}")]
        public ref struct ArrayEnumerator
        {
            private int _curIdx;
            private JwtDocument _document;
            private readonly int _endIdxOrVersion;

            internal ArrayEnumerator(JwtElement target)
            {
                _curIdx = -1;

                var value = target.GetRawValue();
                if (!TryParse(value, target.GetArrayLength(), out _document!))
                {
                    ThrowHelper.ThrowFormatException_MalformedJson();
                }

                Debug.Assert(target.TokenType == JsonTokenType.StartArray);
                _endIdxOrVersion = value.Length;
            }

            /// <inheritdoc />
            public JwtElement Current
            {
                get
                {
                    if (_curIdx < 0)
                    {
                        return default;
                    }

                    return new JwtElement(_document, _curIdx);
                }
            }

            /// <summary>
            ///   Returns an enumerator that iterates through a collection.
            /// </summary>
            /// <returns>
            ///   An <see cref="ArrayEnumerator"/> value that can be used to iterate
            ///   through the array.
            /// </returns>
            public ArrayEnumerator GetEnumerator()
            {
                ArrayEnumerator ator = this;
                ator._curIdx = -1;
                return ator;
            }

            /// <inheritdoc />
            public void Dispose()
            {
                _curIdx = _endIdxOrVersion;
                _document?.Dispose();
            }

            /// <inheritdoc />
            public void Reset()
            {
                _curIdx = -1;
            }

            /// <inheritdoc />
            public bool MoveNext()
            {
                if (_curIdx >= _endIdxOrVersion)
                {
                    return false;
                }

                if (_curIdx < 0)
                {
                    _curIdx = 0;
                }
                else
                {
                    _curIdx += DbRow.Size;//= _document.GetEndIndex(_curIdx, includeEndElement: true);
                }

                return _curIdx < _endIdxOrVersion;
            }

            private static bool TryParse(ReadOnlyMemory<byte> utf8Array, int count, out JwtDocument? document)
            {
                ReadOnlySpan<byte> utf8JsonSpan = utf8Array.Span;
                var database = new MetadataDb(count * DbRow.Size);

                var reader = new Utf8JsonReader(utf8JsonSpan);
                if (reader.Read())
                {
                    JsonTokenType tokenType = reader.TokenType;
                    if (tokenType == JsonTokenType.StartArray)
                    {
                        while (reader.Read())
                        {
                            tokenType = reader.TokenType;
                            int tokenStart = (int)reader.TokenStartIndex;

                            if (tokenType == JsonTokenType.EndArray)
                            {
                                break;
                            }
                            else if (tokenType == JsonTokenType.PropertyName)
                            {
                                goto Error;
                            }

                            // Since the input payload is contained within a Span,
                            // token start index can never be larger than int.MaxValue (i.e. utf8JsonSpan.Length).
                            Debug.Assert(reader.TokenStartIndex <= int.MaxValue);
                            if (tokenType == JsonTokenType.String)
                            {
                                // Adding 1 to skip the start quote will never overflow
                                Debug.Assert(tokenStart < int.MaxValue);
                                database.Append(JsonTokenType.String, tokenStart + 1, reader.ValueSpan.Length);
                            }
                            else if (tokenType == JsonTokenType.Number)
                            {
                                database.Append(JsonTokenType.Number, tokenStart, reader.ValueSpan.Length);
                            }
                            else if (tokenType == JsonTokenType.StartObject)
                            {
                                int itemCount = SkipArrayOrObject(ref reader);
                                int tokenEnd = (int)reader.TokenStartIndex;
                                int index = database.Length;
                                database.Append(JsonTokenType.StartObject, tokenStart, tokenEnd - tokenStart + 1);
                                database.SetNumberOfRows(index, itemCount);
                            }
                            else if (tokenType == JsonTokenType.StartArray)
                            {
                                int itemCount = SkipArrayOrObject(ref reader);

                                int index = database.Length;
                                int tokenEnd = (int)reader.TokenStartIndex;
                                database.Append(JsonTokenType.StartArray, tokenStart, tokenEnd - tokenStart + 1);
                                database.SetNumberOfRows(index, itemCount);
                            }
                            else
                            {
                                Debug.Assert(tokenType >= JsonTokenType.True && tokenType <= JsonTokenType.Null);
                                database.Append(tokenType, tokenStart, reader.ValueSpan.Length);
                            }
                        }
                    }
                }

                Debug.Assert(reader.BytesConsumed == utf8JsonSpan.Length);
                database.TrimExcess();

                document = new JwtDocument(utf8Array, database, null);
                return true;

            Error:
                document = null;
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

        }
    }

    /// <summary>
    ///   Represents a single member for a JSON object.
    /// </summary>
    [DebuggerDisplay("{DebuggerDisplay,nq}")]
    public readonly struct JwtMember
    {
        /// <summary>
        ///   The value of this property.
        /// </summary>
        public JwtElement Value { get; }
        private readonly string? _name;

        internal JwtMember(JwtElement value, string? name = null)
        {
            Value = value;
            _name = name;
        }

        /// <summary>
        ///   The name of this property.
        /// </summary>
        public string Name => _name ?? Value.GetPropertyName();

        /// <summary>
        ///   Compares <paramref name="text" /> to the name of this property.
        /// </summary>
        /// <param name="text">The text to compare against.</param>
        /// <returns>
        ///   <see langword="true" /> if the name of this property matches <paramref name="text"/>,
        ///   <see langword="false" /> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="Type"/> is not <see cref="JsonTokenType.PropertyName"/>.
        /// </exception>
        /// <remarks>
        ///   This method is functionally equal to doing an ordinal comparison of <paramref name="text" /> and
        ///   <see cref="Name" />, but can avoid creating the string instance.
        /// </remarks>
        public bool NameEquals(string? text)
        {
            return NameEquals(text.AsSpan());
        }

        /// <summary>
        ///   Compares the text represented by <paramref name="utf8Text" /> to the name of this property.
        /// </summary>
        /// <param name="utf8Text">The UTF-8 encoded text to compare against.</param>
        /// <returns>
        ///   <see langword="true" /> if the name of this property has the same UTF-8 encoding as
        ///   <paramref name="utf8Text" />, <see langword="false" /> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="Type"/> is not <see cref="JsonTokenType.PropertyName"/>.
        /// </exception>
        /// <remarks>
        ///   This method is functionally equal to doing an ordinal comparison of <paramref name="utf8Text" /> and
        ///   <see cref="Name" />, but can avoid creating the string instance.
        /// </remarks>
        public bool NameEquals(ReadOnlySpan<byte> utf8Text)
        {
            return Value.TextEqualsHelper(utf8Text, isPropertyName: true, shouldUnescape: true);
        }

        /// <summary>
        ///   Compares <paramref name="text" /> to the name of this property.
        /// </summary>
        /// <param name="text">The text to compare against.</param>
        /// <returns>
        ///   <see langword="true" /> if the name of this property matches <paramref name="text"/>,
        ///   <see langword="false" /> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value's <see cref="Type"/> is not <see cref="JsonTokenType.PropertyName"/>.
        /// </exception>
        /// <remarks>
        ///   This method is functionally equal to doing an ordinal comparison of <paramref name="text" /> and
        ///   <see cref="Name" />, but can avoid creating the string instance.
        /// </remarks>
        public bool NameEquals(ReadOnlySpan<char> text)
        {
            return Value.TextEqualsHelper(text, isPropertyName: true);
        }

        internal bool EscapedNameEquals(ReadOnlySpan<byte> utf8Text)
        {
            return Value.TextEqualsHelper(utf8Text, isPropertyName: true, shouldUnescape: false);
        }

        ///// <summary>
        /////   Write the property into the provided writer as a named JSON object property.
        ///// </summary>
        ///// <param name="writer">The writer.</param>
        ///// <exception cref="ArgumentNullException">
        /////   The <paramref name="writer"/> parameter is <see langword="null"/>.
        ///// </exception>
        ///// <exception cref="ArgumentException">
        /////   This <see cref="Name"/>'s length is too large to be a JSON object property.
        ///// </exception>
        ///// <exception cref="InvalidOperationException">
        /////   This <see cref="Value"/>'s <see cref="JsonElement.ValueKind"/> would result in an invalid JSON.
        ///// </exception>
        ///// <exception cref="ObjectDisposedException">
        /////   The parent <see cref="JsonDocument"/> has been disposed.
        ///// </exception>>
        //public void WriteTo(Utf8JsonWriter writer)
        //{
        //    if (writer == null)
        //    {
        //        throw new ArgumentNullException(nameof(writer));
        //    }

        //    writer.WritePropertyName(Name);
        //    Value.WriteTo(writer);
        //}

        /// <summary>
        ///   Provides a <see cref="string"/> representation of the property for
        ///   debugging purposes.
        /// </summary>
        /// <returns>
        ///   A string containing the un-interpreted value of the property, beginning
        ///   at the declaring open-quote and ending at the last character that is part of
        ///   the value.
        /// </returns>
        public override string ToString()
        {
            return Value.GetPropertyRawText();
        }

        private string DebuggerDisplay
            => Value.ValueKind == JsonValueKind.Undefined ? "<Undefined>" : $"\"{ToString()}\"";
    }
}