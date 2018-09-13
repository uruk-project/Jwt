// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a <typeparamref name="TDescriptor"/> as payload.
    /// </summary>
    public class JweDescriptor<TDescriptor> : EncryptedJwtDescriptor<TDescriptor>, IJwtPayloadDescriptor where TDescriptor : JwsDescriptor, new()
    {
        private static readonly string[] DefaultRequiredClaims = Array.Empty<string>();

        public JweDescriptor()
            : base(new JObject(), new TDescriptor())
        {
        }
        
        public JweDescriptor(TDescriptor payload)
            : base(new JObject(), payload)
        {
        }

        public JweDescriptor(JObject header, TDescriptor payload)
            : base(header, payload)
        {
        }

        public string Subject { get => Payload.Subject; set => Payload.Subject = value; }
        public IReadOnlyList<string> Audiences { get => Payload.Audiences; set => Payload.Audiences = value; }
        public DateTime? ExpirationTime { get => Payload.ExpirationTime; set => Payload.ExpirationTime = value; }
        public DateTime? IssuedAt { get => Payload.IssuedAt; set => Payload.IssuedAt = value; }
        public string Issuer { get => Payload.Issuer; set => Payload.Issuer = value; }
        public string JwtId { get => Payload.JwtId; set => Payload.JwtId = value; }
        public DateTime? NotBefore { get => Payload.NotBefore; set => Payload.NotBefore = value; }

        public override string Encode(EncodingContext context)
        {
            var payload = Payload.Encode(context);
            var rawData = EncryptToken(context, payload);

            return rawData;
        }

        public override void Validate()
        {
            Payload?.Validate();
            base.Validate();
        }
    }
}
