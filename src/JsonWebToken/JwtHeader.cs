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

        internal JwtObject Inner => _inner ?? (_inner = new JwtObject());

        /// <summary>
        /// Gets the signature algorithm that was used to create the signature.
        /// </summary>
        public ReadOnlySpan<byte> Alg
            => _signatureAlgorithm?.Utf8Name ?? _keyManagementAlgorithm?.Utf8Name;

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
        public ReadOnlySpan<byte> Enc => _encryptionAlgorithm?.Utf8Name;

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
        public string? X5t => Inner.TryGetValue(HeaderParameters.TagUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the URL of the JWK used to sign the token.
        /// </summary>
        public string? Jku => Inner.TryGetValue(HeaderParameters.JkuUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the URL of the certificate used to sign the token
        /// </summary>
        public string? X5u => Inner.TryGetValue(HeaderParameters.X5uUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the algorithm used to compress the token.
        /// </summary>
        public ReadOnlySpan<byte> Zip => _compressionAlgorithm?.Utf8Name;

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
        public string? IV => Inner.TryGetValue(HeaderParameters.IVUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the Authentication Tag used for AES GCM encryption.
        /// </summary>
        public string? Tag => Inner.TryGetValue(HeaderParameters.TagUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the Crit header.
        /// </summary>
        public IList<string> Crit
        {
            get
            {
                if (!(_inner is null))
                {
                    if (_inner.TryGetValue(HeaderParameters.CritUtf8, out var property) && !(property.Value is null))
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
                return Inner.TryGetValue(HeaderParameters.EpkUtf8, out var property) && !(property.Value is null) ? ECJwk.FromJwtObject((JwtObject)property.Value) : null;
            }
        }

        /// <summary>
        /// Gets the Agreement PartyUInfo used for ECDH key agreement.
        /// </summary>
        public string? Apu => Inner.TryGetValue(HeaderParameters.ApuUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the Agreement PartyVInfo used for ECDH key agreement.
        /// </summary>
        public string? Apv => Inner.TryGetValue(HeaderParameters.ApvUtf8, out var property) ? (string?)property.Value : null;
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

            return _inner.TryGetValue(key, out value);
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
}
