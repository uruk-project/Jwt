using JsonWebTokens.Validations;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace JsonWebTokens
{
    public class TokenValidationBuilder
    {
        private const string LifetimeValidationName = "";
        public const int DefaultMaximumTokenSizeInBytes = 1024 * 1024 * 2; // 2MB
        private readonly List<IValidation> _validations = new List<IValidation>();
        private int _maximumTokenSizeInBytes = DefaultMaximumTokenSizeInBytes;
        private bool _hasSignatureValidation = false;

        public TokenValidationBuilder Clear()
        {
            _validations.Clear();
            return this;
        }

        protected TokenValidationBuilder RemoveValidation(IValidation validation)
        {
            if (validation == null)
            {
                throw new ArgumentNullException(nameof(validation));
            }

            _validations.Remove(validation);
            return this;
        }

        protected TokenValidationBuilder RemoveValidation<TValidation>() where TValidation : IValidation
        {
            _validations.RemoveAll(v => v.GetType() == typeof(TValidation));
            return this;
        }

        public TokenValidationBuilder AddValidation(IValidation validation)
        {
            if (validation == null)
            {
                throw new ArgumentNullException(nameof(validation));
            }

            _validations.Add(validation);
            return this;
        }

        public TokenValidationBuilder MaximumTokenSizeInBytes(int bytes)
        {
            if (bytes <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bytes), ErrorMessages.FormatInvariant(ErrorMessages.MustBeGreaterThanZero, nameof(bytes), bytes));
            }

            _maximumTokenSizeInBytes = bytes;
            return this;
        }

        public TokenValidationBuilder IgnoreSignature()
        {
            _hasSignatureValidation = true;
            return RemoveValidation<SignatureValidation>();
        }
        public TokenValidationBuilder AcceptUnsecureToken()
        {
            _hasSignatureValidation = true;
            _validations.Add(new SignatureValidation(new EmptyKeyProvider(), true));
            return this;
        }

        public TokenValidationBuilder RequireSignature(IKeyProvider keyProvider)
        {
            _hasSignatureValidation = true;
            _validations.Add(new SignatureValidation(keyProvider, false));
            return this;
        }

        public TokenValidationBuilder RequireSignature(string jsonWebKeyUrl, HttpMessageHandler handler = null)
        {
            RequireSignature(new JwksKeyProvider(jsonWebKeyUrl, handler));
            return this;
        }

        public TokenValidationBuilder RequireSignature(JsonWebKey key)
        {
            return RequireSignature(new JsonWebKeySet(key));
        }

        public TokenValidationBuilder RequireSignature(IEnumerable<JsonWebKey> keys)
        {
            return RequireSignature(new JsonWebKeySet(keys));
        }

        public TokenValidationBuilder RequireSignature(JsonWebKeySet keySet)
        {
            return RequireSignature(new StaticKeyProvider(keySet));
        }

        public TokenValidationBuilder RequireSignature(IEnumerable<IKeyProvider> keyProviders)
        {
            foreach (var keyProvider in keyProviders)
            {
                RequireSignature(keyProvider);
            }

            return this;
        }

        public TokenValidationBuilder RequireClaim(string requiredClaim)
        {
            return AddValidation(new RequiredClaimValidation<JObject>(requiredClaim));
        }

        public TokenValidationBuilder RequireHeader(string requiredHeader)
        {
            return AddValidation(null);
        }

        public TokenValidationBuilder AddLifetimeValidation(bool requireExpirationTime = true, int clockSkew = 300)
        {
            if (clockSkew <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(clockSkew), ErrorMessages.FormatInvariant(ErrorMessages.MustBeGreaterThanTimeSpanZero, nameof(clockSkew), clockSkew));
            }

            _validations.Add(new LifetimeValidation(requireExpirationTime, clockSkew));
            return this;
        }

        public TokenValidationBuilder RequireAudience(string audience)
        {
            if (string.IsNullOrEmpty(audience))
            {
                throw new ArgumentNullException(nameof(audience));
            }

            _validations.Add(new AudienceValidation(new[] { audience }));
            return this;
        }

        public TokenValidationBuilder RequireAudience(IEnumerable<string> audiences)
        {
            if (audiences == null)
            {
                throw new ArgumentNullException(nameof(audiences));
            }

            _validations.Add(new AudienceValidation(audiences));
            return this;
        }

        public TokenValidationBuilder RequireIssuer(string issuer)
        {
            if (string.IsNullOrEmpty(issuer))
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            _validations.Add(new IssuerValidation(issuer));
            return this;
        }

        public TokenValidationBuilder AddTokenReplayValidation(ITokenReplayCache tokenReplayCache)
        {
            if (tokenReplayCache == null)
            {
                throw new ArgumentNullException(nameof(tokenReplayCache));
            }

            _validations.Add(new TokenReplayValidation(tokenReplayCache));
            return this;
        }

        protected virtual void Validate()
        {
            if (!_hasSignatureValidation)
            {
                throw new InvalidOperationException(ErrorMessages.FormatInvariant("Signature validation must be either defined by calling the method '{0}' or explicitly ignored by calling the '{1}' method.", nameof(RequireSignature), nameof(AcceptUnsecureToken)));
            }
        }

        public TokenValidationParameters Build()
        {
            Validate();

            var parameters = new TokenValidationParameters(_validations);
            parameters.MaximumTokenSizeInBytes = _maximumTokenSizeInBytes;
            return parameters;
        }

        private class EmptyKeyProvider : IKeyProvider
        {
            private static readonly JsonWebKeySet EmptyJwks = new JsonWebKeySet();

            public JsonWebKeySet GetKeys(JObject header)
            {
                return EmptyJwks;
            }
        }
    }
}
