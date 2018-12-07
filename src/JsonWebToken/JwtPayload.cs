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
        ///  Gets the claim for a specified key in the current <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public new JToken this[string key] => TryGetValue(key, out var value) ? JToken.FromObject(value) : null;

        /// <summary>
        /// Gets the 'audience' claim as a list of strings.
        /// </summary>
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

        /// <summary>
        /// Gets the 'expiration time' claim.
        /// </summary>
        public long? Exp => GetValue<long?>(Claims.Exp);

        /// <summary>
        /// Gets the 'JWT ID' claim.
        /// </summary>
        public string Jti => GetValue<string>(Claims.Jti);

        /// <summary>
        /// Gets the 'issued at' claim.
        /// </summary>
        public long? Iat => GetValue<long?>(Claims.Iat);

        /// <summary>
        /// Gets the 'issuer' claim.
        /// </summary>
        public string Iss => GetValue<string>(Claims.Iss);

        /// <summary>
        /// Gets the 'not before' claim.
        /// </summary>
        public long? Nbf
        {
            get
            {
                return GetValue<long?>(Claims.Nbf);
            }
        }

        /// <summary>
        /// Gets the 'subject' claim.
        /// </summary>
        public string Sub => GetValue<string>(Claims.Sub);

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