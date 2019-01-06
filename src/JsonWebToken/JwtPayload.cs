// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the claims contained in the JWT.
    /// </summary>
    public sealed class JwtPayload : Dictionary<string, object>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class.
        /// </summary>
        public JwtPayload()
            : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class.
        /// </summary>
        /// <param name="inner"></param>
        public JwtPayload(Dictionary<string, object> inner)
            : base(inner)
        {
        }

        /// <summary>
        ///  Gets the claim for a specified key in the current <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public new object this[string key]
        {
            get
            {
                switch (key)
                {
                    case Claims.Iss:
                        return Iss;
                    case Claims.Exp:
                        return Exp;
                    case Claims.Aud:
                        return Aud;
                    case Claims.Jti:
                        return Jti;
                    case Claims.Sub:
                        return Sub;
                    case Claims.Nbf:
                        return Nbf;
                    case Claims.Iat:
                        return Iat;
                    default:
                        return TryGetValue(key, out var value) ? value : null;
                }
            }

            set => base[key] = value;
        }

        /// <summary>
        /// Gets the 'audience' claim as a list of strings.
        /// </summary>
        public IList<string> Aud { get; set; }

        /// <summary>
        /// Gets the 'expiration time' claim.
        /// </summary>
        public long? Exp { get; set; }

        /// <summary>
        /// Gets the 'JWT ID' claim.
        /// </summary>
        public string Jti { get; set; }

        /// <summary>
        /// Gets the 'issued at' claim.
        /// </summary>
        public long? Iat { get; set; }

        /// <summary>
        /// Gets the 'issuer' claim.
        /// </summary>
        public string Iss { get; set; }

        /// <summary>
        /// Gets the 'not before' claim.
        /// </summary>
        public long? Nbf { get; set; }

        /// <summary>
        /// Gets the 'subject' claim.
        /// </summary>
        public string Sub { get; set; }

        /// <summary>
        /// Gets the claim for a specified key in the current <see cref="JwtPayload"/>.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="key"></param>
        /// <returns></returns>
        public T GetValue<T>(string key)
        {
            if (TryGetValue(key, out var value) && value is T tValue)
            {
                return tValue;
            }

            return default;
        }
    }
}