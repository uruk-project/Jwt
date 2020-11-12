// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the payload of a JWT, in a lightweight, read-only form. 
    /// </summary>
    /// <remarks>
    /// This class utilizes resources from pooled memory to minimize the garbage collector (GC)
    /// impact in high-usage scenarios. Failure to properly Dispose this object will result in
    /// the memory not being returned to the pool.
    /// </remarks>
    public sealed class JwtPayloadDocument : IDisposable
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

        /// <summary>
        /// Gets the validation control bits.
        /// </summary>
        public byte Control => _control;
        internal bool InvalidAudience => (_control & InvalidAudienceFlag) == InvalidAudienceFlag;
        internal bool MissingAudience => (_control & MissingAudienceFlag) == MissingAudienceFlag;
        internal bool InvalidIssuer => (_control & InvalidIssuerFlag) == InvalidIssuerFlag;
        internal bool MissingIssuer => (_control & MissingIssuerFlag) == MissingIssuerFlag;
        internal bool MissingExpirationTime => (_control & MissingExpirationFlag) == MissingExpirationFlag;
        internal bool Expired => (_control & ExpiredFlag) == ExpiredFlag;
        internal bool NotYetValid => (_control & NotYetFlag) == NotYetFlag;

        /// <summary>
        /// Gets the raw binary value of the current <see cref="JwtPayloadDocument"/>.
        /// </summary>
        public ReadOnlyMemory<byte> RawValue => _document.RawValue;

        private JwtPayloadDocument(JwtDocument document, byte control)
        {
            _document = document;
            _control = control;
        }

        internal static bool TryParsePayload(ReadOnlyMemory<byte> utf8Payload, byte[]? buffer, TokenValidationPolicy policy, [NotNullWhen(true)] out JwtPayloadDocument? payload, [NotNullWhen(false)] out TokenValidationError? error)
        {
            ReadOnlySpan<byte> utf8JsonSpan = utf8Payload.Span;
            var database = new MetadataDb(utf8Payload.Length);
            byte control = policy.Control;

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
                                        CheckStringAudience(ref reader, ref control, policy);
                                        break;

                                    case JwtClaims.Iss:
                                        CheckIssuer(ref reader, ref control, policy);
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
                                        if (!TryCheckExpirationTime(ref reader, ref control, policy))
                                        {
                                            error = TokenValidationError.MalformedToken("The claim 'exp' must be an integral number.");
                                            goto Error;
                                        }
                                        break;

                                    case JwtClaims.Nbf:
                                        if (!TryCheckNotBefore(ref reader, ref control, policy))
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
                            int itemCount = Utf8JsonReaderHelper.SkipObject(ref reader);
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
                                itemCount = CheckArrayAudience(ref reader, ref control, policy);
                            }
                            else
                            {
                                itemCount = Utf8JsonReaderHelper.SkipArray(ref reader);
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

            payload = new JwtPayloadDocument(new JwtDocument(utf8Payload, database, buffer), control);
            error = null;
            return true;

        Error:
            payload = null;
            return false;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void CheckIssuer(ref Utf8JsonReader reader, ref byte validationControl, TokenValidationPolicy policy)
        {
            if (policy.RequireIssuer)
            {
                validationControl &= unchecked((byte)~JwtPayload.MissingIssuerFlag);
                var issuerBinary = policy.RequiredIssuersBinary;
                for (int i = 0; i < issuerBinary.Length; i++)
                {
                    if (reader.ValueTextEquals(issuerBinary[i]))
                    {
                        validationControl &= unchecked((byte)~TokenValidationPolicy.IssuerFlag);
                        break;
                    }
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
                && (policy.Control & JwtPayload.ExpiredFlag) == JwtPayload.ExpiredFlag)
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

        /// <inheritdoc />
        public void Dispose()
        {
            _document.Dispose();
        }

        /// <summary>
        /// Determines whether the <see cref="JwtPayloadDocument"/> contains the specified claim.
        /// </summary>
        /// <param name="claimName"></param>
        /// <returns></returns>
        public bool ContainsClaim(string claimName)
        {
            return _document.ContainsKey(claimName);
        }

        /// <summary>
        /// Determines whether the <see cref="JwtPayloadDocument"/> contains the specified claim.
        /// </summary>
        /// <param name="claimName"></param>
        /// <returns></returns>
        public bool ContainsClaim(ReadOnlySpan<byte> claimName)
        {
            return _document.ContainsKey(claimName);
        }

        /// <summary>
        ///   Looks for a claim named <paramref name="claimName"/> in the current JWT, returning
        ///   whether or not such a claim existed. When the claim exists <paramref name="value"/>
        ///   is assigned to the value of that claim.
        /// </summary>
        /// <param name="claimName">Name of the claim to find.</param>
        /// <param name="value">Receives the value of the located claim.</param>
        /// <returns>
        ///   <see langword="true"/> if the claim was found, <see langword="false"/> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JwtDocument"/> has been disposed.
        /// </exception>
        public bool TryGetClaim(string claimName, out JwtElement value)
        {
            return _document.TryGetProperty(claimName, out value);
        }

        /// <summary>
        ///   Looks for a claim named <paramref name="claimName"/> in the current JWT, returning
        ///   whether or not such a claim existed. When the claim exists <paramref name="value"/>
        ///   is assigned to the value of that claim.
        /// </summary>
        /// <param name="claimName">Name of the claim to find.</param>
        /// <param name="value">Receives the value of the located claim.</param>
        /// <returns>
        ///   <see langword="true"/> if the claim was found, <see langword="false"/> otherwise.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JwtDocument"/> has been disposed.
        /// </exception>
        public bool TryGetClaim(ReadOnlySpan<byte> claimName, out JwtElement value)
        {
            return _document.TryGetProperty(claimName, out value);
        }

        /// <summary>
        ///   Looks for a claim named <paramref name="claimName"/> in the current JWT, returning
        ///   the value of that claim.
        /// </summary>
        /// <param name="claimName">Name of the claim to find.</param>
        /// <returns>
        ///  The value of the located claim.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JwtDocument"/> has been disposed.
        /// </exception>
        /// <exception cref="KeyNotFoundException">
        ///   The <paramref name="claimName"/> is not found.
        /// </exception>
        public JwtElement this[string claimName]
        {
            get
            {
                if (_document.TryGetProperty(claimName, out var value))
                {
                    return value;
                }

                throw new KeyNotFoundException();
            }
        }

        /// <summary>
        ///   Looks for a claim named <paramref name="claimName"/> in the current JWT, returning
        ///   the value of that claim.
        /// </summary>
        /// <param name="claimName">Name of the claim to find.</param>
        /// <returns>
        ///  The value of the located claim.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        ///   This value is not <see cref="JsonValueKind.Object"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///   The parent <see cref="JwtDocument"/> has been disposed.
        /// </exception>
        /// <exception cref="KeyNotFoundException">
        ///   The <paramref name="claimName"/> is not found.
        /// </exception>
        public JwtElement this[ReadOnlySpan<byte> claimName]
        {
            get
            {
                if (_document.TryGetProperty(claimName, out var value))
                {
                    return value;
                }

                throw new KeyNotFoundException();
            }
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            return _document.ToString();
        }
    }
}