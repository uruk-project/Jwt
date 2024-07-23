// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace JsonWebToken
{
    public partial class JwsDescriptor
    {
        /// <summary>Gets or sets the algorithm header.</summary>
        [Obsolete("This property is obsolete. Use the constructor for passing this value instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public SignatureAlgorithm? Algorithm
            => throw new NotImplementedException();

        /// <summary>Gets or sets the value of the 'sub' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Payload.Add(JwtClaimNames.Sub, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public string? Subject
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the value of the 'jti' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Payload.Add(JwtClaimNames.Jti, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public string? JwtId
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the value of the 'aud' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Payload.Add(JwtClaimNames.Aud, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public string? Audience
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the value of the 'aud' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Payload.Add(JwtClaimNames.Aud, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public List<string>? Audiences
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the value of the 'exp' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Payload.Add(JwtClaimNames.Exp, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public DateTime? ExpirationTime
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the value of the 'iss' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Payload.Add(JwtClaimNames.Iss, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public string? Issuer
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the value of the 'iat' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Payload.Add(JwtClaimNames.Iat, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public DateTime? IssuedAt
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the value of the 'nbf' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Payload.Add(JwtClaimNames.Nbf, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public DateTime? NotBefore
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }
    }
}