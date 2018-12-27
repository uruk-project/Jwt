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
                    case "iss":
                        return Iss;
                    case "exp":
                        return Exp;
                    case "aud":
                        return Aud;
                    case "jti":
                        return Jti;
                    case "sub":
                        return Sub;
                    case "nbf":
                        return Nbf;
                    case "iat":
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
#if NETCOREAPP3_0
        public IList<string> Aud { get; set; }
#else
        public IList<string> Aud 
        {
            get
            {
                if (!TryGetValue(Claims.Aud, out var token))
                {
                    return null;
                }

                if (token is string sValue)
                {
                    return new[] { sValue };
                }

                if (token is IList<string> lValue)
                {
                    return lValue;
                }

                return null;
            }
        }
#endif

        /// <summary>
        /// Gets the 'expiration time' claim.
        /// </summary>
#if NETCOREAPP3_0
        public long? Exp { get; set; }
#else
        public long? Exp => GetValue<long?>(Claims.Exp);
#endif

        /// <summary>
        /// Gets the 'JWT ID' claim.
        /// </summary>
#if NETCOREAPP3_0
        public string Jti { get; set; }
#else
        public string Jti => GetValue<string>(Claims.Jti);
#endif

        /// <summary>
        /// Gets the 'issued at' claim.
        /// </summary>
#if NETCOREAPP3_0
        public long? Iat { get; set; }
#else
        public long? Iat => GetValue<long?>(Claims.Iat);
#endif

        /// <summary>
        /// Gets the 'issuer' claim.
        /// </summary>
#if NETCOREAPP3_0
        public string Iss { get; set; }
#else
        public string Iss => GetValue<string>(Claims.Iss);
#endif

        /// <summary>
        /// Gets the 'not before' claim.
        /// </summary>
#if NETCOREAPP3_0
        public long? Nbf { get; set; }
#else
        public long? Nbf => GetValue<long?>(Claims.Nbf);
#endif

        /// <summary>
        /// Gets the 'subject' claim.
        /// </summary>
#if NETCOREAPP3_0
        public string Sub { get; set; }
#else
        public string Sub => GetValue<string>(Claims.Sub);
#endif

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