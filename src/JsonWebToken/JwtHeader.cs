// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the cryptographic operations applied to the JWT and optionally 
    /// any additional properties of the JWT. 
    /// </summary>
    public sealed class JwtHeader
    {
        private JwtObject? _inner;
        private SignatureAlgorithm? _signatureAlgorithm;
        private KeyManagementAlgorithm? _keyManagementAlgorithm;
        private EncryptionAlgorithm? _encryptionAlgorithm;
        private CompressionAlgorithm? _compressionAlgorithm;
        private string? _kid;
        private string? _typ;
        private string? _cty;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
        /// </summary>
        /// <param name="inner"></param>
        public JwtHeader(JwtObject inner)
        {
            _inner = inner;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
        /// </summary>
        public JwtHeader()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
        /// </summary>
        /// <param name="json"></param>   
        public static JwtHeader FromJson(string json)
        {
            return JwtHeaderParser.ParseHeader(Utf8.GetBytes(json), TokenValidationPolicy.NoValidation);
        }

        internal JwtObject Inner => _inner ??= new JwtObject();

        /// <summary>
        /// Gets the signature algorithm that was used to create the signature.
        /// </summary>
        public ReadOnlySpan<byte> Alg
            => _signatureAlgorithm is null ? _keyManagementAlgorithm is null ? default : _keyManagementAlgorithm.Utf8Name : _signatureAlgorithm.Utf8Name;

        /// <summary>
        /// Gets the signature algorithm (alg) that was used to create the signature.
        /// </summary>
        public SignatureAlgorithm? SignatureAlgorithm
        {
            get => _signatureAlgorithm;
            set => _signatureAlgorithm = value;
        }

        /// <summary>
        /// Gets the key management algorithm (alg).
        /// </summary>
        public KeyManagementAlgorithm? KeyManagementAlgorithm
        {
            get => _keyManagementAlgorithm;
            set => _keyManagementAlgorithm = value;
        }

        /// <summary>
        /// Gets the content type (Cty) of the token.
        /// </summary>
        public string? Cty
        {
            get => _cty;
            set => _cty = value;
        }

        /// <summary>
        /// Gets the encryption algorithm (enc) of the token.
        /// </summary>
        public ReadOnlySpan<byte> Enc => _encryptionAlgorithm is null ? default : _encryptionAlgorithm.Utf8Name;

        /// <summary>
        /// Gets the encryption algorithm (enc) of the token.
        /// </summary>
        public EncryptionAlgorithm? EncryptionAlgorithm
        {
            get => _encryptionAlgorithm;
            set => _encryptionAlgorithm = value;
        }

        /// <summary>
        /// Gets the key identifier for the key used to sign the token.
        /// </summary>
        public string? Kid
        {
            get => _kid;
            set => _kid = value;
        }

        /// <summary>
        /// Gets the mime type (Typ) of the token.
        /// </summary>
        public string? Typ
        {
            get => _typ;
            set => _typ = value;
        }

        /// <summary>
        /// Gets the thumbprint of the certificate used to sign the token.
        /// </summary>
        public string? X5t => Inner.TryGetProperty(HeaderParameters.TagUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the URL of the JWK used to sign the token.
        /// </summary>
        public string? Jku => Inner.TryGetProperty(HeaderParameters.JkuUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the URL of the certificate used to sign the token
        /// </summary>
        public string? X5u => Inner.TryGetProperty(HeaderParameters.X5uUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the algorithm used to compress the token.
        /// </summary>
        public ReadOnlySpan<byte> Zip => _compressionAlgorithm is null ? default : _compressionAlgorithm.Utf8Name;

        /// <summary>
        /// Gets the compression algorithm (zip) of the token.
        /// </summary>
        public CompressionAlgorithm? CompressionAlgorithm
        {
            get => _compressionAlgorithm;
            set => _compressionAlgorithm = value;
        }
        /// <summary>
        /// Gets the Initialization Vector used for AES GCM encryption.
        /// </summary>
        public string? IV => Inner.TryGetProperty(HeaderParameters.IVUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the Authentication Tag used for AES GCM encryption.
        /// </summary>
        public string? Tag => Inner.TryGetProperty(HeaderParameters.TagUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the Crit header.
        /// </summary>
        public IList<string> Crit
        {
            get
            {
                if (!(_inner is null))
                {
                    if (_inner.TryGetProperty(HeaderParameters.CritUtf8, out var property) && !(property.Value is null))
                    {
                        if (property.Type is JwtTokenType.Array)
                        {
                            var list = new List<string>();
                            var array = (JwtArray)property.Value;
                            for (int i = 0; i < array.Count; i++)
                            {
                                object? value = array[i].Value;
                                if (!(value is null))
                                {
                                    list.Add((string)value);
                                }
                            }

                            return list;
                        }
                        else if (property.Type is JwtTokenType.String)
                        {
                            return new List<string> { (string)property.Value };
                        }
                    }
                }

                return Array.Empty<string>();
            }
        }

        internal List<KeyValuePair<string, ICriticalHeaderHandler>>? CriticalHeaderHandlers { get; set; }

#if SUPPORT_ELLIPTIC_CURVE
        /// <summary>
        /// Gets the ephemeral key used for ECDH key agreement.
        /// </summary>
        public ECJwk? Epk
        {
            get
            {
                return Inner.TryGetProperty(HeaderParameters.EpkUtf8, out var property) && !(property.Value is null) ? ECJwk.FromJwtObject((JwtObject)property.Value) : null;
            }
        }

        /// <summary>
        /// Gets the Agreement PartyUInfo used for ECDH key agreement.
        /// </summary>
        public string? Apu => Inner.TryGetProperty(HeaderParameters.ApuUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the Agreement PartyVInfo used for ECDH key agreement.
        /// </summary>
        public string? Apv => Inner.TryGetProperty(HeaderParameters.ApvUtf8, out var property) ? (string?)property.Value : null;
#endif

        /// <summary>
        /// Gets the <see cref="JwtProperty"/> associated with the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool TryGetValue(ReadOnlySpan<byte> key, out JwtProperty value)
        {
            if (key.Length == 3)
            {
                switch (IntegerMarshal.ReadUInt24(key))
                {
                    case JwtHeaderParser.Enc:
                        if (_encryptionAlgorithm is null)
                        {
                            value = default;
                            return false;
                        }

                        value = new JwtProperty(_encryptionAlgorithm);
                        return true;
                    case JwtHeaderParser.Alg:
                        if (_signatureAlgorithm is null)
                        {
                            if (_keyManagementAlgorithm is null)
                            {
                                value = default;
                                return false;
                            }
                            else
                            {
                                value = new JwtProperty(_keyManagementAlgorithm);
                                return true;
                            }
                        }
                        else
                        {
                            value = new JwtProperty(_signatureAlgorithm);
                            return true;
                        }

                    case JwtHeaderParser.Zip:
                        if (_compressionAlgorithm is null)
                        {
                            value = default;
                            return false;
                        }

                        value = new JwtProperty(_compressionAlgorithm);
                        return true;
                }
            }

            if (_inner is null)
            {
                value = default;
                return false;
            }

            return _inner.TryGetProperty(key, out value);
        }

        /// <summary>
        ///  Gets the claim for a specified key in the current <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public object? this[string key]
        {
            get
            {
                switch (key)
                {
                    case "enc":
                        return _encryptionAlgorithm;
                    case "alg":
                        return (object?)_signatureAlgorithm ?? _keyManagementAlgorithm;
                    case "zip":
                        return _compressionAlgorithm;
                    default:
                        if (_inner is null)
                        {
                            return null;
                        }

                        return _inner.TryGetValue(key, out var value) ? value.Value : null;
                }
            }
        }

        /// <summary>
        /// Determines whether the <see cref="JwtHeader"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(string key)
        {
            switch (key)
            {
                case "enc":
                    return _encryptionAlgorithm is null;
                case "alg":
                    return _signatureAlgorithm is null && _keyManagementAlgorithm is null;
                case "zip":
                    return _compressionAlgorithm is null;
                default:
                    if (_inner is null)
                    {
                        return false;
                    }

                    return _inner.ContainsKey(Utf8.GetBytes(key));
            }
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();
                if (!(_signatureAlgorithm is null))
                {
                    writer.WriteString(HeaderParameters.AlgUtf8, _signatureAlgorithm.Utf8Name);
                }
                else if (!(_keyManagementAlgorithm is null))
                {
                    writer.WriteString(HeaderParameters.AlgUtf8, _keyManagementAlgorithm.Utf8Name);
                }

                if (!(_encryptionAlgorithm is null))
                {
                    writer.WriteString(HeaderParameters.EncUtf8, _encryptionAlgorithm.Utf8Name);
                }

                if (!(_compressionAlgorithm is null))
                {
                    writer.WriteString(HeaderParameters.ZipUtf8, _compressionAlgorithm.Utf8Name);
                }

                if (!(_kid is null))
                {
                    writer.WriteString(HeaderParameters.KidUtf8, _kid);
                }

                if (!(_cty is null))
                {
                    writer.WriteString(HeaderParameters.CtyUtf8, _cty);
                }

                if (!(_typ is null))
                {
                    writer.WriteString(HeaderParameters.TypUtf8, _typ);
                }

                if (!(_inner is null))
                {
                    _inner.WriteTo(writer);
                }

                writer.WriteEndObject();
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }
    }

    public sealed class JwtHeaderDocument
    {
        private JsonDocument _inner;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
        /// </summary>
        /// <param name="inner"></param>
        public JwtHeaderDocument(JsonDocument inner)
        {
            _inner = inner;
        }

        ///// <summary>
        ///// Initializes a new instance of the <see cref="JwtHeader"/> class.
        ///// </summary>
        //public JwtHeader()
        //{
        //}

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
        /// </summary>
        /// <param name="json"></param>   
        public static JwtHeader FromJson(string json)
        {
            return JwtHeaderParser.ParseHeader(Utf8.GetBytes(json), TokenValidationPolicy.NoValidation);
        }

        /// <summary>
        /// Gets the signature algorithm that was used to create the signature.
        /// </summary>
        public ReadOnlySpan<byte> Alg
            => _inner.RootElement.TryGetProperty(HeaderParameters.AlgUtf8, out var property) ? Utf8.GetBytes(property.GetString()!) : null;

        /// <summary>
        /// Gets the signature algorithm (alg) that was used to create the signature.
        /// </summary>
        public SignatureAlgorithm? SignatureAlgorithm
            => SignatureAlgorithm.TryParse(Alg, out var alg) ? alg : null;

        /// <summary>
        /// Gets the key management algorithm (alg).
        /// </summary>
        public KeyManagementAlgorithm? KeyManagementAlgorithm
            => KeyManagementAlgorithm.TryParse(Alg, out var alg) ? alg : null;

        /// <summary>
        /// Gets the content type (Cty) of the token.
        /// </summary>
        public string? Cty
            => _inner.RootElement.TryGetProperty(HeaderParameters.CtyUtf8, out var property) ? property.GetString()! : null;

        /// <summary>
        /// Gets the encryption algorithm (enc) of the token.
        /// </summary>
        public ReadOnlySpan<byte> Enc
            => _inner.RootElement.TryGetProperty(HeaderParameters.EncUtf8, out var property) ? Utf8.GetBytes(property.GetString()!) : null;

        /// <summary>
        /// Gets the encryption algorithm (enc) of the token.
        /// </summary>
        public EncryptionAlgorithm? EncryptionAlgorithm
                 => EncryptionAlgorithm.TryParse(Enc, out var alg) ? alg : null;

        /// <summary>
        /// Gets the key identifier for the key used to sign the token.
        /// </summary>
        public string? Kid
            => _inner.RootElement.TryGetProperty(HeaderParameters.KidUtf8, out var property) ? property.GetString()! : null;

        /// <summary>
        /// Gets the mime type (Typ) of the token.
        /// </summary>
        public string? Typ
            => _inner.RootElement.TryGetProperty(HeaderParameters.TypUtf8, out var property) ? property.GetString()! : null;

        /// <summary>
        /// Gets the thumbprint of the certificate used to sign the token.
        /// </summary>
        public string? X5t => _inner.RootElement.TryGetProperty(HeaderParameters.TagUtf8, out var property) ? (string?)property.GetString() : null;

        /// <summary>
        /// Gets the URL of the JWK used to sign the token.
        /// </summary>
        public string? Jku => _inner.RootElement.TryGetProperty(HeaderParameters.JkuUtf8, out var property) ? (string?)property.GetString() : null;

        /// <summary>
        /// Gets the URL of the certificate used to sign the token
        /// </summary>
        public string? X5u => _inner.RootElement.TryGetProperty(HeaderParameters.X5uUtf8, out var property) ? (string?)property.GetString() : null;

        /// <summary>
        /// Gets the algorithm used to compress the token.
        /// </summary>
        public ReadOnlySpan<byte> Zip
            => _inner.RootElement.TryGetProperty(HeaderParameters.ZipUtf8, out var property) ? Utf8.GetBytes(property.GetString()!) : null;

        /// <summary>
        /// Gets the compression algorithm (zip) of the token.
        /// </summary>
        public CompressionAlgorithm? CompressionAlgorithm
            => CompressionAlgorithm.TryParse(Zip, out var alg) ? alg : null;

        /// <summary>
        /// Gets the Initialization Vector used for AES GCM encryption.
        /// </summary>
        public string? IV => _inner.RootElement.TryGetProperty(HeaderParameters.IVUtf8, out var property) ? (string?)property.GetString() : null;

        /// <summary>
        /// Gets the Authentication Tag used for AES GCM encryption.
        /// </summary>
        public string? Tag => _inner.RootElement.TryGetProperty(HeaderParameters.TagUtf8, out var property) ? (string?)property.GetString() : null;

        /// <summary>
        /// Gets the Crit header.
        /// </summary>
        public IList<string> Crit
        {
            get
            {
                if (!(_inner is null))
                {
                    if (_inner.RootElement.TryGetProperty(HeaderParameters.CritUtf8, out var property))
                    {
                        if (property.ValueKind is JsonValueKind.Array)
                        {
                            var list = new List<string>();
                            foreach (var item in property.EnumerateArray())
                            {
                                if (item.ValueKind is JsonValueKind.String)
                                {
                                    list.Add(item.GetString()!);
                                }
                            }

                            return list;
                        }
                    }
                }

                return Array.Empty<string>();
            }
        }

        internal List<KeyValuePair<string, ICriticalHeaderHandler>>? CriticalHeaderHandlers { get; set; }

#if SUPPORT_ELLIPTIC_CURVE
        /// <summary>
        /// Gets the ephemeral key used for ECDH key agreement.
        /// </summary>
        public ECJwk? Epk
        {
            get
            {
                return _inner.RootElement.TryGetProperty(HeaderParameters.EpkUtf8, out var property) && (property.ValueKind is JsonValueKind.Object) ? ECJwk.FromJsonElement(property) : null;
            }
        }

        /// <summary>
        /// Gets the Agreement PartyUInfo used for ECDH key agreement.
        /// </summary>
        public string? Apu => _inner.RootElement.TryGetProperty(HeaderParameters.ApuUtf8, out var property) ? (string?)property.GetString() : null;

        /// <summary>
        /// Gets the Agreement PartyVInfo used for ECDH key agreement.
        /// </summary>
        public string? Apv => _inner.RootElement.TryGetProperty(HeaderParameters.ApvUtf8, out var property) ? (string?)property.GetString() : null;
#endif

        /// <summary>
        /// Gets the <see cref="JwtProperty"/> associated with the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool TryGetValue(ReadOnlySpan<byte> key, out JsonElement value)
        {
            return _inner.RootElement.TryGetProperty(key, out value);
        }

        /// <summary>
        ///  Gets the claim for a specified key in the current <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public object? this[string key]
        {
            get
            {
                return _inner.RootElement.GetProperty(key);
            }
        }

        /// <summary>
        /// Determines whether the <see cref="JwtHeader"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(string key)
        {
            return _inner.RootElement.TryGetProperty(key, out var _);
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                //writer.WriteStartObject();
                _inner.WriteTo(writer);
                //writer.WriteEndObject();
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }
    }

    //    public sealed class JwtHeaderDocument
    //    {
    //        private readonly JsonDocument _inner;
    //        private SignatureAlgorithm? _signatureAlgorithm;
    //        private KeyManagementAlgorithm? _keyManagementAlgorithm;
    //        private EncryptionAlgorithm? _encryptionAlgorithm;
    //        private CompressionAlgorithm? _compressionAlgorithm;
    //        private string? _kid;
    //        private string? _typ;
    //        private string? _cty;

    //        /// <summary>
    //        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
    //        /// </summary>
    //        /// <param name="inner"></param>
    //        public JwtHeaderDocument(JsonDocument inner)
    //        {
    //            _inner = inner;
    //        }

    //        /// <summary>
    //        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
    //        /// </summary>
    //        public JwtHeaderDocument()
    //        {
    //        }

    //        /// <summary>
    //        /// Initializes a new instance of the <see cref="JwtHeaderDocument"/> class.
    //        /// </summary>
    //        /// <param name="json"></param>   
    //        public static JwtHeaderDocument FromJson(string json)
    //        {
    //            JwtDocument.TryReadHeader(Utf8.GetBytes(json), TokenValidationPolicy.NoValidation, 0, out var header);
    //            return header;
    //        }

    //        internal JsonDocument Inner => _inner;

    //        /// <summary>
    //        /// Gets the signature algorithm that was used to create the signature.
    //        /// </summary>
    //        public ReadOnlySpan<byte> Alg
    //            => _signatureAlgorithm is null ? _keyManagementAlgorithm is null ? default : _keyManagementAlgorithm.Utf8Name : _signatureAlgorithm.Utf8Name;

    //        /// <summary>
    //        /// Gets the signature algorithm (alg) that was used to create the signature.
    //        /// </summary>
    //        public SignatureAlgorithm? SignatureAlgorithm
    //        {
    //            get => _signatureAlgorithm;
    //            set => _signatureAlgorithm = value;
    //        }

    //        /// <summary>
    //        /// Gets the key management algorithm (alg).
    //        /// </summary>
    //        public KeyManagementAlgorithm? KeyManagementAlgorithm
    //        {
    //            get => _keyManagementAlgorithm;
    //            set => _keyManagementAlgorithm = value;
    //        }

    //        /// <summary>
    //        /// Gets the content type (Cty) of the token.
    //        /// </summary>
    //        public string? Cty
    //        {
    //            get => _cty;
    //            set => _cty = value;
    //        }

    //        /// <summary>
    //        /// Gets the encryption algorithm (enc) of the token.
    //        /// </summary>
    //        public ReadOnlySpan<byte> Enc => _encryptionAlgorithm is null ? default : _encryptionAlgorithm.Utf8Name;

    //        /// <summary>
    //        /// Gets the encryption algorithm (enc) of the token.
    //        /// </summary>
    //        public EncryptionAlgorithm? EncryptionAlgorithm
    //        {
    //            get => _encryptionAlgorithm;
    //            set => _encryptionAlgorithm = value;
    //        }

    //        /// <summary>
    //        /// Gets the key identifier for the key used to sign the token.
    //        /// </summary>
    //        public string? Kid
    //        {
    //            get => _kid;
    //            set => _kid = value;
    //        }

    //        /// <summary>
    //        /// Gets the mime type (Typ) of the token.
    //        /// </summary>
    //        public string? Typ
    //        {
    //            get => _typ;
    //            set => _typ = value;
    //        }

    //        /// <summary>
    //        /// Gets the thumbprint of the certificate used to sign the token.
    //        /// </summary>
    //        public string? X5t => _inner.RootElement.TryGetProperty(HeaderParameters.TagUtf8, out var property) ? property.GetString() : null;

    //        /// <summary>
    //        /// Gets the URL of the JWK used to sign the token.
    //        /// </summary>
    //        public string? Jku => Inner.RootElement.TryGetProperty(HeaderParameters.JkuUtf8, out var property) ? property.GetString() : null;

    //        /// <summary>
    //        /// Gets the URL of the certificate used to sign the token
    //        /// </summary>
    //        public string? X5u => Inner.RootElement.TryGetProperty(HeaderParameters.X5uUtf8, out var property) ? property.GetString() : null;

    //        /// <summary>
    //        /// Gets the algorithm used to compress the token.
    //        /// </summary>
    //        public ReadOnlySpan<byte> Zip => _compressionAlgorithm is null ? default : _compressionAlgorithm.Utf8Name;

    //        /// <summary>
    //        /// Gets the compression algorithm (zip) of the token.
    //        /// </summary>
    //        public CompressionAlgorithm? CompressionAlgorithm
    //        {
    //            get => _compressionAlgorithm;
    //            set => _compressionAlgorithm = value;
    //        }
    //        /// <summary>
    //        /// Gets the Initialization Vector used for AES GCM encryption.
    //        /// </summary>
    //        public string? IV => Inner.RootElement.TryGetProperty(HeaderParameters.IVUtf8, out var property) ? property.GetString() : null;

    //        /// <summary>
    //        /// Gets the Authentication Tag used for AES GCM encryption.
    //        /// </summary>
    //        public string? Tag => Inner.RootElement.TryGetProperty(HeaderParameters.TagUtf8, out var property) ? property.GetString() : null;

    //        /// <summary>
    //        /// Gets the Crit header.
    //        /// </summary>
    //        public IList<string> Crit
    //        {
    //            get
    //            {
    //                if (_inner.RootElement.TryGetProperty(HeaderParameters.CritUtf8, out var property) && property.ValueKind == JsonValueKind.Array)
    //                {
    //                    List<string>? list = new List<string>();
    //                    foreach (var item in property.EnumerateArray())
    //                    {
    //                        if (item.ValueKind == JsonValueKind.String)
    //                        {
    //                            list.Add(item.GetString()!);
    //                        }
    //                    }

    //                    return list;
    //                }

    //                return Array.Empty<string>();
    //            }
    //        }

    //        internal List<KeyValuePair<string, ICriticalHeaderHandler>>? CriticalHeaderHandlers { get; set; }

    //#if SUPPORT_ELLIPTIC_CURVE
    //        /// <summary>
    //        /// Gets the ephemeral key used for ECDH key agreement.
    //        /// </summary>
    //        public ECJwk? Epk
    //        {
    //            get
    //            {
    //                return Inner.RootElement.TryGetProperty(HeaderParameters.EpkUtf8, out var property) && property.ValueKind is JsonValueKind.Object ? ECJwk.FromJsonElement(property) : null;
    //            }
    //        }

    //        /// <summary>
    //        /// Gets the Agreement PartyUInfo used for ECDH key agreement.
    //        /// </summary>
    //        public string? Apu => Inner.RootElement.TryGetProperty(HeaderParameters.ApuUtf8, out var property) ? property.GetString() : null;

    //        /// <summary>
    //        /// Gets the Agreement PartyVInfo used for ECDH key agreement.
    //        /// </summary>
    //        public string? Apv => Inner.RootElement.TryGetProperty(HeaderParameters.ApvUtf8, out var property) ? property.GetString() : null;
    //#endif

    //        /// <summary>
    //        /// Gets the <see cref="JwtProperty"/> associated with the specified key.
    //        /// </summary>
    //        /// <param name="key"></param>
    //        /// <param name="value"></param>
    //        /// <returns></returns>
    //        public bool TryGetValue(ReadOnlySpan<byte> key, out JwtProperty value)
    //        {
    //            if (key.Length == 3)
    //            {
    //                switch (IntegerMarshal.ReadUInt24(key))
    //                {
    //                    case JwtHeaderParser.Enc:
    //                        if (_encryptionAlgorithm is null)
    //                        {
    //                            value = default;
    //                            return false;
    //                        }

    //                        value = new JwtProperty(_encryptionAlgorithm);
    //                        return true;
    //                    case JwtHeaderParser.Alg:
    //                        if (_signatureAlgorithm is null)
    //                        {
    //                            if (_keyManagementAlgorithm is null)
    //                            {
    //                                value = default;
    //                                return false;
    //                            }
    //                            else
    //                            {
    //                                value = new JwtProperty(_keyManagementAlgorithm);
    //                                return true;
    //                            }
    //                        }
    //                        else
    //                        {
    //                            value = new JwtProperty(_signatureAlgorithm);
    //                            return true;
    //                        }

    //                    case JwtHeaderParser.Zip:
    //                        if (_compressionAlgorithm is null)
    //                        {
    //                            value = default;
    //                            return false;
    //                        }

    //                        value = new JwtProperty(_compressionAlgorithm);
    //                        return true;
    //                }
    //            }

    //            if (_inner is null)
    //            {
    //                value = default;
    //                return false;
    //            }

    //            return _inner.RootElement.TryGetProperty(key, out value);
    //        }

    //        /// <summary>
    //        ///  Gets the claim for a specified key in the current <see cref="JwtPayload"/>.
    //        /// </summary>
    //        /// <param name="key"></param>
    //        /// <returns></returns>
    //        public object? this[string key]
    //        {
    //            get
    //            {
    //                switch (key)
    //                {
    //                    case "enc":
    //                        return _encryptionAlgorithm;
    //                    case "alg":
    //                        return (object?)_signatureAlgorithm ?? _keyManagementAlgorithm;
    //                    case "zip":
    //                        return _compressionAlgorithm;
    //                    default:
    //                        if (_inner is null)
    //                        {
    //                            return null;
    //                        }

    //                        return _inner.RootElement.TryGetProperty(key, out var value) ? value.Value : null;
    //                }
    //            }
    //        }

    //        /// <summary>
    //        /// Determines whether the <see cref="JwtHeader"/> contains the specified key.
    //        /// </summary>
    //        /// <param name="key"></param>
    //        /// <returns></returns>
    //        public bool ContainsKey(string key)
    //        {
    //            switch (key)
    //            {
    //                case "enc":
    //                    return _encryptionAlgorithm is null;
    //                case "alg":
    //                    return _signatureAlgorithm is null && _keyManagementAlgorithm is null;
    //                case "zip":
    //                    return _compressionAlgorithm is null;
    //                default:
    //                    if (_inner is null)
    //                    {
    //                        return false;
    //                    }

    //                    return _inner.ContainsKey(Utf8.GetBytes(key));
    //            }
    //        }

    //        /// <inheritsdoc />
    //        public override string ToString()
    //        {
    //            using var bufferWriter = new PooledByteBufferWriter();
    //            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
    //            {
    //                writer.WriteStartObject();
    //                if (!(_signatureAlgorithm is null))
    //                {
    //                    writer.WriteString(HeaderParameters.AlgUtf8, _signatureAlgorithm.Utf8Name);
    //                }
    //                else if (!(_keyManagementAlgorithm is null))
    //                {
    //                    writer.WriteString(HeaderParameters.AlgUtf8, _keyManagementAlgorithm.Utf8Name);
    //                }

    //                if (!(_encryptionAlgorithm is null))
    //                {
    //                    writer.WriteString(HeaderParameters.EncUtf8, _encryptionAlgorithm.Utf8Name);
    //                }

    //                if (!(_compressionAlgorithm is null))
    //                {
    //                    writer.WriteString(HeaderParameters.ZipUtf8, _compressionAlgorithm.Utf8Name);
    //                }

    //                if (!(_kid is null))
    //                {
    //                    writer.WriteString(HeaderParameters.KidUtf8, _kid);
    //                }

    //                if (!(_cty is null))
    //                {
    //                    writer.WriteString(HeaderParameters.CtyUtf8, _cty);
    //                }

    //                if (!(_typ is null))
    //                {
    //                    writer.WriteString(HeaderParameters.TypUtf8, _typ);
    //                }

    //                if (!(_inner is null))
    //                {
    //                    _inner.WriteTo(writer);
    //                }

    //                writer.WriteEndObject();
    //            }

    //            var input = bufferWriter.WrittenSpan;
    //            return Utf8.GetString(input);
    //        }
    //    }
}
