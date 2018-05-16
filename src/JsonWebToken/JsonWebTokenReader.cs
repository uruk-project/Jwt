using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JsonWebToken
{
    public class JsonWebTokenReader
    {
        private static readonly HashSet<char> JwsCharacters = new HashSet<char>(JwtConstants.JwsCompactSerializationCharacters);
        private readonly ITokenReplayCache _tokenReplayCache;
        private readonly IList<IKeyProvider> _keyProviders;

        public JsonWebTokenReader(IEnumerable<IKeyProvider> keyProviders, ITokenReplayCache tokenReplayCache = null)
        {
            _keyProviders = keyProviders.ToArray();
            _tokenReplayCache = tokenReplayCache;
        }

        public JsonWebTokenReader(IKeyProvider keyProvider)
            : this(new[] { keyProvider })
        {
        }

        public JsonWebTokenReader(JsonWebKeySet jwks)
            : this(new StaticKeyProvider(jwks))
        {
        }

        public JsonWebTokenReader(JsonWebKey jwk)
            : this(new JsonWebKeySet(jwk))
        {
        }

        /// <summary>
        /// Reads and validates a 'JSON Web Token' (JWT) encoded as a JWS or JWE in Compact Serialized Format.
        /// </summary>
        /// <param name="token">the JWT encoded as JWE or JWS</param>
        /// <param name="validationParameters">Contains validation parameters for the <see cref="JsonWebToken"/>.</param>
        /// <param name="validatedToken">The <see cref="JsonWebToken"/> that was validated.</param>
        public TokenValidationResult TryReadToken(string token, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
            {
                throw new ArgumentNullException(nameof(validationParameters));
            }

            validationParameters.ThrowIfInvalid();

            if (string.IsNullOrWhiteSpace(token))
            {
                return TokenValidationResult.MalformedToken();
            }

            if (token.Length > validationParameters.MaximumTokenSizeInBytes)
            {
                return TokenValidationResult.MalformedToken();
            }

            int segmentCount = GetSegmentCount(token);
            if (segmentCount == JwtConstants.JweSegmentCount)
            {
                var result = ReadJwtToken(token, segmentCount, validationParameters);
                if (!result.Succedeed)
                {
                    return result;
                }

                var jwtToken = result.Token;
                if (string.IsNullOrEmpty(jwtToken.Header.Enc))
                {
                    return TokenValidationResult.MissingEncryptionAlgorithm(jwtToken);
                }

                var keys = GetContentEncryptionKeys(jwtToken);

                string decryptedToken = null;
                for (int i = 0; i < keys.Count; i++)
                {
                    decryptedToken = DecryptToken(jwtToken, keys[i]);
                    if (decryptedToken != null)
                    {
                        break;
                    }
                }

                if (decryptedToken == null)
                {
                    return TokenValidationResult.DecryptionFailed(jwtToken);
                }

                int innerSegmentCount = GetSegmentCount(decryptedToken);
                if (!CanReadToken(decryptedToken, validationParameters))
                {
                    // The decrypted payload is not a JWT
                    jwtToken.PlainText = decryptedToken;
                    return TokenValidationResult.Success(jwtToken);
                }

                var decryptionResult = ReadJwtToken(decryptedToken, innerSegmentCount, validationParameters);
                if (!decryptionResult.Succedeed)
                {
                    return decryptionResult;
                }

                var decryptedJwt = decryptionResult.Token;
                jwtToken.InnerToken = decryptedJwt;
                return ValidateToken(decryptedJwt, validationParameters);
            }
            else if (segmentCount == JwtConstants.JwsSegmentCount)
            {
                var result = ReadJwtToken(token, segmentCount, validationParameters);
                if (!result.Succedeed)
                {
                    return result;
                }

                var jwtToken = result.Token;
                return ValidateToken(jwtToken, validationParameters);
            }

            return TokenValidationResult.MalformedToken();
        }

        private TokenValidationResult ValidateToken(JsonWebToken token, TokenValidationParameters validationParameters)
        {
            var result = ValidateSignature(token, validationParameters);
            if (!result.Succedeed)
            {
                return result;
            }

            result = ValidateTokenPayload(token, validationParameters);
            return result;
        }

        private static int GetSegmentCount(string token)
        {
            int segmentCount = 1;
            int next = -1;
            while ((next = token.IndexOf('.', next + 1)) != -1)
            {
                segmentCount++;
                if (segmentCount > JwtConstants.MaxJwtSegmentCount)
                {
                    break;
                }
            }

            return segmentCount;
        }

        private bool CanReadToken(string token, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return false;
            }

            if (token.Length * 2 > validationParameters.MaximumTokenSizeInBytes)
            {
                return false;
            }

            for (int i = 0; i < token.Length; i++)
            {
                if (!JwsCharacters.Contains(token[i]))
                {
                    return false;
                }
            }

            return true;
        }

        private TokenValidationResult ReadJwtToken(string token, int segmentCount, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrEmpty(token))
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (!CanReadToken(token, validationParameters))
            {
                return TokenValidationResult.MalformedToken();
            }

            JsonWebToken jwt;
            if (segmentCount == JwtConstants.JwsSegmentCount)
            {
                jwt = JsonWebToken.FromJws(token);
            }
            else
            {
                jwt = JsonWebToken.FromJwe(token);
            }

            return TokenValidationResult.Success(jwt);
        }

        /// <summary>
        /// Validates the JSON payload of a <see cref="JsonWebToken"/>.
        /// </summary>
        /// <param name="jwtToken">The token to validate.</param>
        /// <param name="validationParameters">Contains validation parameters for the <see cref="JsonWebToken"/>.</param>
        /// <returns>A <see cref="TokenValidationResult"/> with the JWT if succeeded.</returns>
        private TokenValidationResult ValidateTokenPayload(JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {
            var expires = jwtToken.Payload.Exp;
            var result = ValidateLifetime(jwtToken.Payload.Nbf, expires, jwtToken, validationParameters);
            if (!result.Succedeed)
            {
                return result;
            }

            result = ValidateAudience(jwtToken.Audiences, jwtToken, validationParameters);
            if (!result.Succedeed)
            {
                return result;
            }

            result = ValidateIssuer(jwtToken.Issuer, jwtToken, validationParameters);
            if (!result.Succedeed)
            {
                return result;
            }

            result = ValidateTokenReplay(expires, jwtToken, validationParameters);
            if (!result.Succedeed)
            {
                return result;
            }

            return TokenValidationResult.Success(jwtToken);
        }

        private bool ValidateSignature(byte[] encodedBytes, byte[] signature, JsonWebKey key, string algorithm, TokenValidationParameters validationParameters)
        {
            var signatureProvider = key.CreateSignatureProvider(algorithm, false);
            if (signatureProvider == null)
            {
                return false;
            }

            try
            {
                return signatureProvider.Verify(encodedBytes, signature);
            }
            finally
            {
                key.ReleaseSignatureProvider(signatureProvider);
            }
        }

        private TokenValidationResult ValidateSignature(JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {
            if (jwtToken == null)
            {
                throw new ArgumentNullException(nameof(jwtToken));
            }

            if (validationParameters == null)
            {
                throw new ArgumentNullException(nameof(validationParameters));
            }

            if (string.IsNullOrEmpty(jwtToken.RawSignature))
            {
                if (validationParameters.RequireSignedTokens)
                {
                    return TokenValidationResult.MissingSignature(jwtToken);
                }
                else
                {
                    return TokenValidationResult.Success(jwtToken);
                }
            }

            bool keysTried = false;
            byte[] signatureBytes;
            try
            {
                signatureBytes = Base64UrlEncoder.DecodeBytes(jwtToken.RawSignature);
            }
            catch (FormatException)
            {
                return TokenValidationResult.MalformedSignature(jwtToken);
            }

            byte[] encodedBytes = Encoding.UTF8.GetBytes(jwtToken.RawHeader + "." + jwtToken.RawPayload);

            var keys = ResolveSigningKey(jwtToken);
            foreach (var key in keys)
            {
                try
                {
                    if (ValidateSignature(encodedBytes, signatureBytes, key, jwtToken.Header.Alg, validationParameters))
                    {
                        jwtToken.Header.SigningKey = key;
                        return TokenValidationResult.Success(jwtToken);
                    }
                }
                catch
                {
                    // swallow exception
                }

                keysTried = true;
            }

            if (keysTried)
            {
                return TokenValidationResult.InvalidSignature(jwtToken);
            }

            return TokenValidationResult.KeyNotFound(jwtToken);
        }

        private TokenValidationResult ValidateAudience(IEnumerable<string> audiences, JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {
            return Validators.ValidateAudience(audiences, jwtToken, validationParameters);
        }

        private TokenValidationResult ValidateLifetime(int? notBefore, int? expires, JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {
            return Validators.ValidateLifetime(notBefore, expires, jwtToken, validationParameters);
        }

        private TokenValidationResult ValidateIssuer(string issuer, JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {
            return Validators.ValidateIssuer(issuer, jwtToken, validationParameters);
        }

        private TokenValidationResult ValidateTokenReplay(int? expires, JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {
            return Validators.ValidateTokenReplay(expires, jwtToken, validationParameters, _tokenReplayCache);
        }

        private string DecryptToken(JsonWebToken jwtToken, JsonWebKey key)
        {
            var decryptionProvider = key.CreateAuthenticatedEncryptionProvider(jwtToken.Header.Enc);
            if (decryptionProvider == null)
            {
                return null;
            }

            try
            {
                var decryptedToken = decryptionProvider.Decrypt(
                    Base64UrlEncoder.DecodeBytes(jwtToken.RawCiphertext),
                    Encoding.ASCII.GetBytes(jwtToken.RawHeader),
                    Base64UrlEncoder.DecodeBytes(jwtToken.RawInitializationVector),
                    Base64UrlEncoder.DecodeBytes(jwtToken.RawAuthenticationTag));
                if (decryptedToken == null)
                {
                    return null;
                }

                return Encoding.UTF8.GetString(decryptedToken);
            }
            finally
            {
                key.ReleaseAuthenticatedEncryptionProvider(decryptionProvider);
            }
        }

        private IList<JsonWebKey> GetContentEncryptionKeys(JsonWebToken jwtToken)
        {
            var keys = ResolveDecryptionKey(jwtToken);
            if (string.Equals(jwtToken.Header.Alg, SecurityAlgorithms.Direct, StringComparison.Ordinal))
            {
                return keys;
            }

            var unwrappedKeys = new List<JsonWebKey>();
            for (int i = 0; i < keys.Count; i++)
            {
                var key = keys[i];
                KeyWrapProvider kwp = key.CreateKeyWrapProvider(jwtToken.Header.Alg);
                try
                {
                    if (kwp != null)
                    {
                        var unwrappedKey = kwp.UnwrapKey(Base64UrlEncoder.DecodeBytes(jwtToken.RawEncryptedKey));
                        unwrappedKeys.Add(SymmetricJwk.FromByteArray(unwrappedKey));
                    }
                }
                finally
                {
                    key.ReleaseKeyWrapProvider(kwp);
                }
            }

            return unwrappedKeys;
        }

        private IEnumerable<JsonWebKey> ResolveSigningKey(JsonWebToken jwtToken)
        {
            var keys = new List<JsonWebKey>();
            for (int i = 0; i < _keyProviders.Count; i++)
            {
                var keySet = _keyProviders[i].GetKeys(jwtToken);
                if (keySet != null)
                {
                    for (int j = 0; j < keySet.Keys.Count; j++)
                    {
                        var key = keySet.Keys[j];
                        if ((string.IsNullOrWhiteSpace(key.Use) || string.Equals(key.Use, JsonWebKeyUseNames.Sig, StringComparison.Ordinal)) &&
                             (string.Equals(key.Kid, jwtToken.Header.Kid, StringComparison.Ordinal)))
                        {
                            keys.Add(key);
                        }
                    }
                }
            }

            return keys;
        }

        private IList<JsonWebKey> ResolveDecryptionKey(JsonWebToken jwtToken)
        {
            var keys = new List<JsonWebKey>();
            for (int i = 0; i < _keyProviders.Count; i++)
            {
                var keySet = _keyProviders[i].GetKeys(jwtToken);

                for (int j = 0; j < keySet.Keys.Count; j++)
                {
                    var key = keySet.Keys[j];
                    if ((string.IsNullOrWhiteSpace(key.Use) || string.Equals(key.Use, JsonWebKeyUseNames.Enc, StringComparison.Ordinal)) &&
                         (string.Equals(key.Kid, jwtToken.Header.Kid, StringComparison.Ordinal)))
                    {
                        keys.Add(key);
                    }
                }
            }

            return keys;
        }
    }
}
