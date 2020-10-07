using System;
using System.Collections.Generic;
using System.Text.Json;

namespace JsonWebToken
{
    internal ref struct JwtHeaderReader
    {
        private readonly TokenValidationPolicy _policy;
        private Utf8JsonReader _reader;
        private ReadOnlySpan<byte> _headerParameterName;
        private List<KeyValuePair<string, ICriticalHeaderHandler>>? _criticalHeaderHandlers;

        public JwtHeaderReader(ReadOnlySpan<byte> headerData, TokenValidationPolicy policy)
        {
            _policy = policy;
            _reader = new Utf8JsonReader(headerData, isFinalBlock: true, state: default);
            _headerParameterName = default;
            _criticalHeaderHandlers = null;
        }

        public string? GetString()
            => _reader.GetString();
        public bool GetBoolean()
            => _reader.GetBoolean();
        public bool TryGetDouble(out double value)
            => _reader.TryGetDouble(out value);
        public double GetDouble()
            => _reader.GetDouble();
        public bool TryGetInt64(out long value)
            => _reader.TryGetInt64(out value);
        public JsonDocument GetObject()
            => JsonDocument.ParseValue(ref _reader);
        public JwtObject GetJwtObject()
            => JsonParser.ReadJsonObject(ref _reader);
        public T GetObject<T>()
            => JsonSerializer.Deserialize<T>(ref _reader);
        public JsonDocument GetArray()
            => JsonDocument.ParseValue(ref _reader);
        public T[] GetArray<T>()
            => JsonSerializer.Deserialize<T[]>(ref _reader);
        public JwtArray GetJwtArray()
            => JsonParser.ReadJsonArray(ref _reader);
        public string[] GetStringArray()
            => JsonParser.ReadStringArray(ref _reader);

        public bool Read()
        {
            if (_reader.Read() && _reader.TokenType is JsonTokenType.PropertyName)
            {
                _headerParameterName = _reader.ValueSpan;
                return _reader.Read();
            }

            return false;
        }

        public JsonTokenType TokenType => _reader.TokenType;
        public ReadOnlySpan<byte> TokenName => _headerParameterName;
        public ReadOnlySpan<byte> ValueSpan => _reader.ValueSpan;

        internal SignatureAlgorithm GetSignatureAlgorithm()
        {
            var alg = _reader.ValueSpan;
            SignatureAlgorithm? signatureAlgorithm;
            if (!SignatureAlgorithm.TryParse(alg, out signatureAlgorithm))
            {
                if (!SignatureAlgorithm.TryParseSlow(ref _reader, out signatureAlgorithm))
                {
                    signatureAlgorithm = SignatureAlgorithm.Create(_reader.GetString()!);
                }
            }

            return signatureAlgorithm;
        }

        internal KeyManagementAlgorithm GetKeyManagementAlgorithm()
        {
            var alg = _reader.ValueSpan;
            KeyManagementAlgorithm? keyManagementAlgorithm;
            if (!KeyManagementAlgorithm.TryParse(alg, out keyManagementAlgorithm))
            {
                if (!KeyManagementAlgorithm.TryParseSlow(ref _reader, out keyManagementAlgorithm))
                {
                    keyManagementAlgorithm = KeyManagementAlgorithm.Create(_reader.GetString()!);
                }
            }

            return keyManagementAlgorithm;
        }

        internal EncryptionAlgorithm GetEncryptionAlgorithm()
        {
            var alg = _reader.ValueSpan;
            EncryptionAlgorithm? encryptionAlgorithm;
            if (!EncryptionAlgorithm.TryParse(alg, out encryptionAlgorithm))
            {
                if (!EncryptionAlgorithm.TryParseSlow(ref _reader, out encryptionAlgorithm))
                {
                    encryptionAlgorithm = EncryptionAlgorithm.Create(_reader.GetString()!);
                }
            }

            return encryptionAlgorithm;
        }

        internal CompressionAlgorithm GetCompressionAlgorithm()
        {
            ref Utf8JsonReader reader = ref _reader;
            var zip = _reader.ValueSpan;
            CompressionAlgorithm? compressionAlgorithm;
            if (!CompressionAlgorithm.TryParse(zip, out compressionAlgorithm))
            {
                if (!CompressionAlgorithm.TryParseSlow(ref _reader, out compressionAlgorithm))
                {
                    compressionAlgorithm = CompressionAlgorithm.Create(_reader.GetString()!);
                }
            }

            return compressionAlgorithm;
        }

        internal (List<string>, List<KeyValuePair<string, ICriticalHeaderHandler>>?) GetCriticalHeaders()
        {
            var handlers = _policy.CriticalHandlers;
            var criticals = new List<string>();
            List<KeyValuePair<string, ICriticalHeaderHandler>>? criticalHeaderHandlers = null;
            if (handlers.Count != 0)
            {
                criticalHeaderHandlers = new List<KeyValuePair<string, ICriticalHeaderHandler>>(handlers.Count);
                while (_reader.Read() && _reader.TokenType == JsonTokenType.String)
                {
                    string criticalHeader = _reader.GetString()!;
                    criticals.Add(criticalHeader);
                    if (handlers.TryGetValue(criticalHeader, out var handler))
                    {
                        criticalHeaderHandlers.Add(new KeyValuePair<string, ICriticalHeaderHandler>(criticalHeader, handler));
                    }
                    else
                    {
                        criticalHeaderHandlers.Add(new KeyValuePair<string, ICriticalHeaderHandler>(criticalHeader, null!));
                    }
                }

                _criticalHeaderHandlers = criticalHeaderHandlers;

                if (_reader.TokenType != JsonTokenType.EndArray)
                {
                    ThrowHelper.ThrowFormatException_MalformedJson("The 'crit' header parameter must be an array of string.");
                }
            }
            else
            {
                while (_reader.Read() && _reader.TokenType == JsonTokenType.String)
                {
                    string criticalHeader = _reader.GetString()!;
                    criticals.Add(criticalHeader);
                }

                if (_reader.TokenType != JsonTokenType.EndArray)
                {
                    ThrowHelper.ThrowFormatException_MalformedJson("The 'crit' header parameter must be an array of string.");
                }
            }

            return (criticals, criticalHeaderHandlers);
        }

        public bool TryValidateHeader(JwtHeader header, out TokenValidationError error)
        {
            if (!_policy.IgnoreCriticalHeader)
            {
                var handlers = _criticalHeaderHandlers;
                if (handlers != null)
                {
                    for (int i = 0; i < handlers.Count; i++)
                    {
                        KeyValuePair<string, ICriticalHeaderHandler> handler = handlers[i];
                        if (handler.Value is null)
                        {
                            error = TokenValidationError.CriticalHeaderUnsupported(handler.Key);
                            return false;
                        }

                        if (!handler.Value.TryHandle(header, handler.Key))
                        {
                            error = TokenValidationError.InvalidHeader(handler.Key);
                            return false;
                        }
                    }
                }
            }

            error = null;
            return true;
        }

        internal bool ReadFirstBytes()
        {
            return _reader.Read() && _reader.TokenType == JsonTokenType.StartObject;
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