// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace JsonWebToken
{
    public abstract partial class JwtDescriptor
    {
        /// <summary>Gets or sets the key identifier header parameter.</summary>
        [Obsolete("This property is obsolete. Use the method Header.Add(JwHeaderParameterNames.Kid, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public string? KeyId
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the JWKS URL header parameter.</summary>
        [Obsolete("This property is obsolete. Use the method Header.Add(JwHeaderParameterNames.Jku, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public string? JwkSetUrl
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the X509 URL header parameter.</summary>
        [Obsolete("This property is obsolete. Use the method Header.Add(JwHeaderParameterNames.X5u, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public string? X509Url
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the X509 certification chain header.</summary>
        [Obsolete("This property is obsolete. Use the method Header.Add(JwHeaderParameterNames.X5c, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public List<string>? X509CertificateChain
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the X509 certificate SHA-1 thumbprint header parameter.</summary>
        [Obsolete("This property is obsolete. Use the method Header.Add(JwHeaderParameterNames.X5t, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public string? X509CertificateSha1Thumbprint
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the JWT type 'typ' header parameter.</summary>
        [Obsolete("This property is obsolete. Use the constructor or the method Header.Add(JwHeaderParameterNames.Typ, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public string? Type
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the content type header parameter.</summary>
        [Obsolete("This property is obsolete. Use the constructor or the the method Header.Add(JwHeaderParameterNames.Cty, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public string? ContentType
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        /// <summary>Gets or sets the critical header parameter.</summary>
        [Obsolete("This property is obsolete. Use the method Header.Add(JwHeaderParameterNames.Crit, <value>) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public List<string>? Critical
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }
    }
}