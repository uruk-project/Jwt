// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the cryptographic operations applied to the JWT and optionally 
    /// any additional properties of the JWT. 
    /// </summary>
    public sealed class JwtHeader
    {
        private readonly JwtObject _inner;
        private SignatureAlgorithm? _signatureAlgorithm;
        private KeyManagementAlgorithm? _keyManagementAlgorithm;
        private EncryptionAlgorithm? _encryptionAlgorithm;
        private CompressionAlgorithm? _compressionAlgorithm;

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
            _inner = new JwtObject(3);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
        /// </summary>
        /// <param name="json"></param>   
        public static JwtHeader FromJson(string json)
        {
            return JsonHeaderParser.ReadHeader(Encoding.UTF8.GetBytes(json));
        }

        /// <summary>
        /// Gets the signature algorithm that was used to create the signature.
        /// </summary>
        public ReadOnlySpan<byte> Alg
        {
            get
            {
                return _signatureAlgorithm?.Utf8Name ?? _keyManagementAlgorithm?.Utf8Name ?? (_inner.TryGetValue(WellKnownProperty.Alg, out var property) ? (byte[]?)property.Value : default);
            }
        }

        /// <summary>
        /// Gets the signature algorithm (alg) that was used to create the signature.
        /// </summary>
        public SignatureAlgorithm? SignatureAlgorithm
        {
            get => _signatureAlgorithm
                ?? (_inner.TryGetValue(WellKnownProperty.Alg, out var property)
                ? (SignatureAlgorithm.TryParse((byte[]?)property.Value, out var alg) ? alg : null)
                : null);
            set
            {
                _signatureAlgorithm = value;
                if (!(value is null))
                {
                    _inner.Add(new JwtProperty(WellKnownProperty.Alg, value.Utf8Name));
                }
            }
        }

        /// <summary>
        /// Gets the key management algorithm (alg).
        /// </summary>
        public KeyManagementAlgorithm? KeyManagementAlgorithm
        {
            get => _keyManagementAlgorithm ??
                (_inner.TryGetValue(WellKnownProperty.Alg, out var property)
                ? (KeyManagementAlgorithm.TryParse((byte[]?)property.Value, out var alg) ? alg : null)
                : null);
            set
            {
                _keyManagementAlgorithm = value;
                if (!(value is null))
                {
                    _inner.Add(new JwtProperty(WellKnownProperty.Alg, value.Utf8Name));
                }
            }
        }

        /// <summary>
        /// Gets the content type (Cty) of the token.
        /// </summary>
        public ReadOnlySpan<byte> Cty => _inner.TryGetValue(WellKnownProperty.Cty, out var property) ? (byte[]?)property.Value : default;

        /// <summary>
        /// Gets the encryption algorithm (enc) of the token.
        /// </summary>
        public ReadOnlySpan<byte> Enc => _encryptionAlgorithm?.Utf8Name ?? (_inner.TryGetValue(WellKnownProperty.Enc, out var property) ? (byte[]?)property.Value : default);

        /// <summary>
        /// Gets the encryption algorithm (enc) of the token.
        /// </summary>
        public EncryptionAlgorithm? EncryptionAlgorithm
        {
            get => _encryptionAlgorithm ?? (_inner.TryGetValue(WellKnownProperty.Enc, out var property) ? (EncryptionAlgorithm?)property.Value : null);
            set => _encryptionAlgorithm = value;
        }

        /// <summary>
        /// Gets the key identifier for the key used to sign the token.
        /// </summary>
        public string? Kid => _inner.TryGetValue(WellKnownProperty.Kid, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the mime type (Typ) of the token.
        /// </summary>
        public string? Typ => _inner.TryGetValue(WellKnownProperty.Typ, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the thumbprint of the certificate used to sign the token.
        /// </summary>
        public string? X5t => _inner.TryGetValue(HeaderParameters.TagUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the URL of the JWK used to sign the token.
        /// </summary>
        public string? Jku => _inner.TryGetValue(HeaderParameters.JkuUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the URL of the certificate used to sign the token
        /// </summary>
        public string? X5u => _inner.TryGetValue(HeaderParameters.X5uUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the algorithm used to compress the token.
        /// </summary>
        public ReadOnlySpan<byte> Zip => _compressionAlgorithm?.Utf8Name ?? (_inner.TryGetValue(WellKnownProperty.Zip, out var property) ? (byte[]?)property.Value : null);

        /// <summary>
        /// Gets the compression algorithm (zip) of the token.
        /// </summary>
        public CompressionAlgorithm? CompressionAlgorithm
        {
            get => _compressionAlgorithm ?? (_inner.TryGetValue(WellKnownProperty.Zip, out var property) ? (CompressionAlgorithm?)property.Value : null);
            set => _compressionAlgorithm = value;
        }
        /// <summary>
        /// Gets the Initialization Vector used for AES GCM encryption.
        /// </summary>
        public string? IV => _inner.TryGetValue(HeaderParameters.IVUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the Authentication Tag used for AES GCM encryption.
        /// </summary>
        public string? Tag => _inner.TryGetValue(HeaderParameters.TagUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the Crit header.
        /// </summary>
        public IList<string> Crit
        {
            get
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

                return Array.Empty<string>();
            }
        }

#if !NETSTANDARD
        /// <summary>
        /// Gets the ephemeral key used for ECDH key agreement.
        /// </summary>
        public ECJwk? Epk
        {
            get
            {
                return _inner.TryGetValue(HeaderParameters.EpkUtf8, out var property) && !(property.Value is null) ? ECJwk.FromJwtObject((JwtObject)property.Value) : null;
            }
        }

        /// <summary>
        /// Gets the Agreement PartyUInfo used for ECDH key agreement.
        /// </summary>
        public string? Apu => _inner.TryGetValue(HeaderParameters.ApuUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the Agreement PartyVInfo used for ECDH key agreement.
        /// </summary>
        public string? Apv => _inner.TryGetValue(HeaderParameters.ApvUtf8, out var property) ? (string?)property.Value : null;
#endif

        /// <summary>
        /// Gets the <see cref="JwtProperty"/> associated with the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool TryGetValue(ReadOnlySpan<byte> key, out JwtProperty value) => _inner.TryGetValue(key, out value);

        /// <summary>
        ///  Gets the claim for a specified key in the current <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public object? this[string key]
        {
            get
            {
                return _inner.TryGetValue(key, out var value) ? value.Value : null;
            }
        }

        /// <summary>
        /// Determines whether the <see cref="JwtHeader"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(string key)
        {
            return _inner.ContainsKey(Encoding.UTF8.GetBytes(key));
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            return _inner.ToString();
        }
    }
}
