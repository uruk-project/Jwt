using System;
using System.Collections.Generic;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    public ref struct JwtPayloadReader
    {
        private readonly ReadOnlySpan<byte> _payloadData;
        private readonly TokenValidationPolicy _policy;
        private Utf8JsonReader _jsonReader;
        private ReadOnlySpan<byte> _claimName;

        public JwtPayloadReader(ReadOnlySpan<byte> payloadData, TokenValidationPolicy policy)
        {
            _payloadData = payloadData;
            _policy = policy;
            _jsonReader = new Utf8JsonReader(payloadData, isFinalBlock: true, state: default);
            _claimName = default;
            ValidationControl = policy.ValidationControl;
        }

        public string? GetString()
            => _jsonReader.GetString();
        public bool GetBoolean()
            => _jsonReader.GetBoolean();
        public bool TryGetDouble(out double value)
            => _jsonReader.TryGetDouble(out value);
        public double GetDouble()
            => _jsonReader.GetDouble();
        public bool TryGetInt64(out long value)
            => _jsonReader.TryGetInt64(out value);
        public JsonDocument GetObject()
            => JsonDocument.ParseValue(ref _jsonReader);
        public JwtObject GetJwtObject()
            => JsonParser.ReadJsonObject(ref _jsonReader);
        public T GetObject<T>()
            => JsonSerializer.Deserialize<T>(ref _jsonReader);
        public JsonDocument GetArray()
            => JsonDocument.ParseValue(ref _jsonReader);
        public T[] GetArray<T>()
            => JsonSerializer.Deserialize<T[]>(ref _jsonReader);
        public JwtArray GetJwtArray()
            => JsonParser.ReadJsonArray(ref _jsonReader);
        public string[] GetStringArray()
            => JsonParser.ReadStringArray(ref _jsonReader);

        public bool Read()
        {
            if (_jsonReader.Read() && _jsonReader.TokenType is JsonTokenType.PropertyName)
            {
                _claimName = _jsonReader.ValueSpan;
                return _jsonReader.Read();
            }

            return false;
        }

        public JsonTokenType ClaimTokenType => _jsonReader.TokenType;
        public ReadOnlySpan<byte> ClaimName => _claimName;
        public ReadOnlySpan<byte> ClaimValue => _jsonReader.ValueSpan;
        public byte ValidationControl { get; private set; }

        internal void EnsureJson()
        {
            if (!_jsonReader.Read() || _jsonReader.TokenType != JsonTokenType.StartObject)
            {
                ThrowHelper.ThrowFormatException_MalformedJson();
            }
        }

        internal bool ValueTextEquals(byte[] vs)
        {
            throw new NotImplementedException();
        }

        public string? GetIssuer()
        {
            string? iss = null; ;
            if (_policy.RequireIssuer)
            {
                if (_jsonReader.ValueTextEquals(_policy.RequiredIssuerBinary))
                {
                    iss = _policy.RequiredIssuer;
                    ValidationControl &= unchecked((byte)~TokenValidationPolicy.IssuerFlag);
                }
                else
                {
                    ValidationControl &= unchecked((byte)~JwtPayload.MissingIssuerFlag);
                }
            }
            else
            {
                iss = _jsonReader.GetString();
            }

            return iss;
        }
        public long GetIssuedAt()
        {
            if (!_jsonReader.TryGetInt64(out long longValue))
            {
                ThrowHelper.ThrowFormatException_MalformedJson("The claim 'iat' must be an integral number.");
            }

            return longValue;
        }
        public long GetExpirationTime()
        {
            if (!_jsonReader.TryGetInt64(out long longValue))
            {
                ThrowHelper.ThrowFormatException_MalformedJson("The claim 'exp' must be an integral number.");
            }

            if (_policy.RequireExpirationTime)
            {
                ValidationControl &= unchecked((byte)~JwtPayload.MissingExpirationFlag);
            }

            if (longValue >= EpochTime.UtcNow - _policy.ClockSkew)
            {
                ValidationControl &= unchecked((byte)~JwtPayload.ExpiredFlag);
            }

            return longValue;
        }

        public long GetNotBefore()
        {
            if (!_jsonReader.TryGetInt64(out long longValue))
            {
                ThrowHelper.ThrowFormatException_MalformedJson("The claim 'nbf' must be an integral number.");
            }

            // the 'nbf' claim is not common. A 2nd call to EpochTime.UtcNow should be rare.
            if (longValue > EpochTime.UtcNow + _policy.ClockSkew && (_policy.ValidationControl & JwtPayload.ExpiredFlag) == JwtPayload.ExpiredFlag)
            {
                ValidationControl |= JwtPayload.NotYetFlag;
            }

            return longValue;
        }

        public string GetStringAudience()
        {
            string aud;
            if (_policy.RequireAudience)
            {
                ValidationControl &= unchecked((byte)~JwtPayload.MissingAudienceFlag);

                var audiencesBinary = _policy.RequiredAudiencesBinary;
                var audiences = _policy.RequiredAudiences;
                for (int i = 0; i < audiencesBinary.Length; i++)
                {
                    if (_jsonReader.ValueTextEquals(audiencesBinary[i]))
                    {
                        aud = audiences[i];
                        ValidationControl &= unchecked((byte)~TokenValidationPolicy.AudienceFlag);
                        goto Found;
                    }
                }
            }

            aud = _jsonReader.GetString()!;

        Found:
            return aud;
        }

        public string[] GetArrayAudience()
        {
            string[] aud;
            if (_policy.RequireAudience)
            {
                var audiences = new List<string>();
                while (_jsonReader.Read() && _jsonReader.TokenType == JsonTokenType.String)
                {
                    var requiredAudiences = _policy.RequiredAudiencesBinary;
                    for (int i = 0; i < requiredAudiences.Length; i++)
                    {
                        if (_jsonReader.ValueTextEquals(requiredAudiences[i]))
                        {
                            ValidationControl &= unchecked((byte)~TokenValidationPolicy.AudienceFlag);
                            break;
                        }
                    }

                    audiences.Add(_jsonReader.GetString()!);
                    ValidationControl &= unchecked((byte)~JwtPayload.MissingAudienceFlag);
                }

                if (_jsonReader.TokenType != JsonTokenType.EndArray)
                {
                    ThrowHelper.ThrowFormatException_MalformedJson("The 'aud' claim must be an array of string or a string.");
                }

                aud = audiences.ToArray();
            }
            else
            {
                aud = JsonParser.ReadStringArray(ref _jsonReader);
            }

            return aud;
        }

        internal bool ReadFirstBytes()
        {
            return _jsonReader.Read() && _jsonReader.TokenType == JsonTokenType.StartObject;
        }
    }

    //public class JwtReader2Tests
    //{
    //    public static JwtHeader ReadHeader(ReadOnlySpan<byte> utf8Token, TokenValidationPolicy policy)
    //    {
    //        var reader = new JwtReader2(utf8Token, policy);

    //        var header = new JwtHeader();
    //        JwtHeaderReader headerReader = reader.HeaderReader;
    //        while (headerReader.Read())
    //        {
    //            var name = headerReader.TokenName;
    //            switch (headerReader.TokenHeaderType)
    //            {
    //                case JwtHeaderParameters.Alg:
    //                    if (reader.SegmentCount == Constants.JwsSegmentCount)
    //                    {
    //                        header.SignatureAlgorithm = headerReader.GetSignatureAlgorithm();
    //                    }
    //                    else if (reader.SegmentCount == Constants.JweSegmentCount)
    //                    {
    //                        header.KeyManagementAlgorithm = headerReader.GetKeyManagementAlgorithm();
    //                    }
    //                    break;
    //                case JwtHeaderParameters.Enc:
    //                    header.EncryptionAlgorithm = headerReader.GetEncryptionAlgorithm();
    //                    break;
    //                case JwtHeaderParameters.Zip:
    //                    header.CompressionAlgorithm = headerReader.GetCompressionAlgorithm();
    //                    break;
    //                case JwtHeaderParameters.Cty:
    //                    header.Cty = headerReader.GetString();
    //                    break;
    //                case JwtHeaderParameters.Typ:
    //                    header.Typ = headerReader.GetString();
    //                    break;
    //                case JwtHeaderParameters.Kid:
    //                    header.Kid = headerReader.GetString();
    //                    break;
    //                case JwtHeaderParameters.Crit:
    //                    var criticals = headerReader.GetCriticalHeaders();
    //                    header.Inner.Add(name, new JwtArray(criticals));
    //                    break;
    //                default:
    //                    switch (headerReader.TokenType)
    //                    {
    //                        case JsonTokenType.StartObject:
    //                            header.Inner.Add(name, headerReader.GetJwtObject());
    //                            break;
    //                        case JsonTokenType.StartArray:
    //                            header.Inner.Add(name, headerReader.GetJwtArray());
    //                            break;
    //                        case JsonTokenType.String:
    //                            header.Inner.Add(name, headerReader.GetString()!);
    //                            break;
    //                        case JsonTokenType.True:
    //                            header.Inner.Add(name, true);
    //                            break;
    //                        case JsonTokenType.False:
    //                            header.Inner.Add(name, false);
    //                            break;
    //                        case JsonTokenType.Null:
    //                            header.Inner.Add(name);
    //                            break;
    //                        case JsonTokenType.Number:
    //                            if (headerReader.TryGetInt64(out long longValue))
    //                            {
    //                                header.Inner.Add(name, longValue);
    //                            }
    //                            else
    //                            {
    //                                header.Inner.Add(name, headerReader.GetDouble());
    //                            }
    //                            break;
    //                        default:
    //                            ThrowHelper.ThrowFormatException_MalformedJson();
    //                            break;
    //                    }
    //                    break;
    //            }
    //        }

    //        if (!(headerReader.TokenType is JsonTokenType.EndObject))
    //        {
    //            ThrowHelper.ThrowFormatException_MalformedJson();
    //        }

    //        return header;
    //    }

    //    public static JwtPayload ReadPayload(ReadOnlySpan<byte> utf8Token, TokenValidationPolicy policy)
    //    {
    //        var reader = new JwtReader2(utf8Token, policy);

    //        var payload = new JwtPayload();
    //        JwtPayloadReader payloadReader = reader.PayloadReader;
    //        byte control = policy.ValidationControl;
    //        while (payloadReader.Read())
    //        {
    //            var name = payloadReader.TokenName;

    //            switch (payloadReader.TokenPayloadType)
    //            {
    //                case JwtClaims.Aud:
    //                    payload.Aud = payloadReader.GetAudience();
    //                    continue;

    //                case JwtClaims.Iss:
    //                    payload.Iss = payloadReader.GetIssuer();
    //                    continue;

    //                case JwtClaims.Exp:
    //                    payload.Exp = payloadReader.GetExpirationTime();
    //                    continue;

    //                case JwtClaims.Iat:
    //                    payload.Iat = payloadReader.GetIssuedAt();
    //                    continue;

    //                case JwtClaims.Nbf:
    //                    payload.Nbf = payloadReader.GetNotBefore();
    //                    continue;

    //                case JwtClaims.Jti:
    //                    payload.Jti = payloadReader.GetString();
    //                    continue;

    //                case JwtClaims.Sub:
    //                    payload.Sub = payloadReader.GetString();
    //                    continue;
    //            }

    //            switch (payloadReader.TokenType)
    //            {
    //                case JsonTokenType.StartObject:
    //                    payload.Inner.Add(name, payloadReader.GetJwtObject());
    //                    break;
    //                case JsonTokenType.StartArray:
    //                    payload.Inner.Add(name, payloadReader.GetJwtArray());
    //                    break;
    //                case JsonTokenType.String:
    //                    payload.Inner.Add(name, payloadReader.GetString()!);
    //                    break;
    //                case JsonTokenType.True:
    //                    payload.Inner.Add(name, true);
    //                    break;
    //                case JsonTokenType.False:
    //                    payload.Inner.Add(name, false);
    //                    break;
    //                case JsonTokenType.Null:
    //                    payload.Inner.Add(name);
    //                    break;
    //                case JsonTokenType.Number:
    //                    long longValue;

    //                    if (payloadReader.TryGetInt64(out longValue))
    //                    {
    //                        payload.Inner.Add(name, longValue);
    //                    }
    //                    else
    //                    {
    //                        payload.Inner.Add(name, payloadReader.GetDouble());
    //                    }
    //                    break;
    //                default:
    //                    ThrowHelper.ThrowFormatException_MalformedJson();
    //                    break;
    //            }
    //        }

    //        if (!(payloadReader.TokenType is JsonTokenType.EndObject))
    //        {
    //            ThrowHelper.ThrowFormatException_MalformedJson();
    //        }

    //        payload.ValidationControl = control;


    //        return payload;
    //    }
    //}
}