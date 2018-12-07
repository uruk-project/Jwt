﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

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

        /// <summary>
        /// Initializes an new instance of <see cref="JweDescriptor"/>.
        /// </summary>
        public JweDescriptor()
            : base(new Dictionary<string, object>(), new TDescriptor())
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JweDescriptor"/>.
        /// </summary>
        /// <param name="payload"></param>
        public JweDescriptor(TDescriptor payload)
            : base(new Dictionary<string, object>(), payload)
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JweDescriptor"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        public JweDescriptor(IDictionary<string, object> header, TDescriptor payload)
            : base(header, payload)
        {
        }

        /// <summary>
        /// Gets or sets the subject 'sub'.
        /// </summary>
        public string Subject { get => Payload.Subject; set => Payload.Subject = value; }

        /// <summary>
        /// Gets or sets the audiences 'aud'.
        /// </summary>
        public IReadOnlyList<string> Audiences { get => Payload.Audiences; set => Payload.Audiences = value; }

        /// <summary>
        /// Gets or sets the expiration time 'exp'.
        /// </summary>
        public DateTime? ExpirationTime { get => Payload.ExpirationTime; set => Payload.ExpirationTime = value; }

        /// <summary>
        /// Gets or sets the issued time 'iat'.
        /// </summary>
        public DateTime? IssuedAt { get => Payload.IssuedAt; set => Payload.IssuedAt = value; }

        /// <summary>
        /// Gets or sets the issuer 'iss'.
        /// </summary>
        public string Issuer { get => Payload.Issuer; set => Payload.Issuer = value; }

        /// <summary>
        /// Gets or set the JWT identifier 'jti'.
        /// </summary>
        public string JwtId { get => Payload.JwtId; set => Payload.JwtId = value; }

        /// <summary>
        /// Gets or sets the "not before" time 'nbf'.
        /// </summary>
        public DateTime? NotBefore { get => Payload.NotBefore; set => Payload.NotBefore = value; }

        /// <inheritsdoc />
        public override string Encode(EncodingContext context)
        {
            var payload = Payload.Encode(context);
            var rawData = EncryptToken(context, payload);

            return rawData;
        }

        /// <inheritsdoc />
        public override void Validate()
        {
            Payload?.Validate();
            base.Validate();
        }
    }
}
