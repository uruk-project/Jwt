// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    public sealed class JwtHeaderDocument : IJwtHeader, IDisposable
    {
        private JsonDocument? _inner;
        private readonly JsonElement _rootElement;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
        /// </summary>
        /// <param name="inner"></param>
        public JwtHeaderDocument(JsonDocument inner)
        {
            _inner = inner;
            _rootElement = inner.RootElement;
        }
        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
        /// </summary>
        /// <param name="root"></param>
        public JwtHeaderDocument(JsonElement root)
        {
            _rootElement = root;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
        /// </summary>
        /// <param name="json"></param>   
        public static JwtHeaderDocument FromJson(string json)
        {
            return new JwtHeaderDocument(JsonDocument.Parse(Utf8.GetBytes(json)));
        }

        /// <summary>
        /// Gets the signature algorithm that was used to create the signature.
        /// </summary>
        public string? Alg
            => _rootElement.TryGetProperty(HeaderParameters.AlgUtf8, out var property) ? property.GetString() : null;

        /// <summary>
        /// Gets the signature algorithm (alg) that was used to create the signature.
        /// </summary>
        public SignatureAlgorithm? SignatureAlgorithm
            => _rootElement.TryGetProperty(HeaderParameters.AlgUtf8, out var property) ? SignatureAlgorithm.TryParse(property, out var alg) ? alg : null : null;

        /// <summary>
        /// Gets the key management algorithm (alg).
        /// </summary>
        public KeyManagementAlgorithm? KeyManagementAlgorithm
            => _rootElement.TryGetProperty(HeaderParameters.AlgUtf8, out var property) ? KeyManagementAlgorithm.TryParse(property, out var alg) ? alg : null : null;

        /// <summary>
        /// Gets the content type (Cty) of the token.
        /// </summary>
        public string? Cty
            => _rootElement.TryGetProperty(HeaderParameters.CtyUtf8, out var property) ? property.GetString()! : null;

        /// <summary>
        /// Gets the encryption algorithm (enc) of the token.
        /// </summary>
        public string? Enc
            => _rootElement.TryGetProperty(HeaderParameters.EncUtf8, out var property) ? property.GetString() : null;

        /// <summary>
        /// Gets the encryption algorithm (enc) of the token.
        /// </summary>
        public EncryptionAlgorithm? EncryptionAlgorithm
            => EncryptionAlgorithm.TryParse(Enc, out var alg) ? alg : null;

        /// <summary>
        /// Gets the key identifier for the key used to sign the token.
        /// </summary>
        public string? Kid
            => _rootElement.TryGetProperty(HeaderParameters.KidUtf8, out var property) ? property.GetString() : null;

        /// <summary>
        /// Gets the mime type (Typ) of the token.
        /// </summary>
        public string? Typ
            => _rootElement.TryGetProperty(HeaderParameters.TypUtf8, out var property) ? property.GetString() : null;

        /// <summary>
        /// Gets the thumbprint of the certificate used to sign the token.
        /// </summary>
        public string? X5t
            => _rootElement.TryGetProperty(HeaderParameters.TagUtf8, out var property) ? (string?)property.GetString() : null;

        /// <summary>
        /// Gets the URL of the JWK used to sign the token.
        /// </summary>
        public string? Jku
            => _rootElement.TryGetProperty(HeaderParameters.JkuUtf8, out var property) ? (string?)property.GetString() : null;

        /// <summary>
        /// Gets the URL of the certificate used to sign the token
        /// </summary>
        public string? X5u
            => _rootElement.TryGetProperty(HeaderParameters.X5uUtf8, out var property) ? (string?)property.GetString() : null;

        /// <summary>
        /// Gets the algorithm used to compress the token.
        /// </summary>
        public string? Zip
            => _rootElement.TryGetProperty(HeaderParameters.ZipUtf8, out var property) ? property.GetString() : null;

        /// <summary>
        /// Gets the compression algorithm (zip) of the token.
        /// </summary>
        public CompressionAlgorithm? CompressionAlgorithm
            => CompressionAlgorithm.TryParse(Zip, out var alg) ? alg : null;

        /// <summary>
        /// Gets the Initialization Vector used for AES GCM encryption.
        /// </summary>
        public string? IV
            => _rootElement.TryGetProperty(HeaderParameters.IVUtf8, out var property) ? (string?)property.GetString() : null;

        /// <summary>
        /// Gets the Authentication Tag used for AES GCM encryption.
        /// </summary>
        public string? Tag
            => _rootElement.TryGetProperty(HeaderParameters.TagUtf8, out var property) ? (string?)property.GetString() : null;

        /// <summary>
        /// Gets the Crit header.
        /// </summary>
        public IList<string> Crit
        {
            get
            {
                if (_rootElement.TryGetProperty(HeaderParameters.CritUtf8, out var property))
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

                return Array.Empty<string>();
            }
        }

        internal List<KeyValuePair<string, ICriticalHeaderHandler>>? CriticalHeaderHandlers { get; set; }

#if SUPPORT_ELLIPTIC_CURVE
        /// <summary>
        /// Gets the ephemeral key used for ECDH key agreement.
        /// </summary>
        public ECJwk? Epk
            => _rootElement.TryGetProperty(HeaderParameters.EpkUtf8, out var property) && (property.ValueKind is JsonValueKind.Object) ? ECJwk.FromJsonElement(property) : null;

        /// <summary>
        /// Gets the Agreement PartyUInfo used for ECDH key agreement.
        /// </summary>
        public string? Apu => _rootElement.TryGetProperty(HeaderParameters.ApuUtf8, out var property) ? (string?)property.GetString() : null;

        /// <summary>
        /// Gets the Agreement PartyVInfo used for ECDH key agreement.
        /// </summary>
        public string? Apv => _rootElement.TryGetProperty(HeaderParameters.ApvUtf8, out var property) ? (string?)property.GetString() : null;
#endif

        /// <summary>
        /// Gets the <see cref="JwtProperty"/> associated with the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool TryGetValue(ReadOnlySpan<byte> key, out System.Text.Json.JsonElement value)
            => _rootElement.TryGetProperty(key, out value);

        /// <summary>
        ///  Gets the claim for a specified key in the current <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public object? this[string key]
            => _rootElement.GetProperty(key);

        /// <summary>
        /// Determines whether the <see cref="JwtHeader"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(string key)
            => _rootElement.TryGetProperty(key, out var _);

        /// <inheritsdoc />
        public override string ToString()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                //writer.WriteStartObject();
                _rootElement.WriteTo(writer);
                //writer.WriteEndObject();
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }

        /// <inheritsdoc />
        public void Dispose()
        {
            _inner?.Dispose();
        }
    }
}
