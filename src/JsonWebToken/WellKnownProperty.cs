// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines the well known JWT properties.
    /// </summary>
    public enum WellKnownProperty : ulong
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,

        /// <summary>
        /// exp
        /// </summary>
        Exp,

        /// <summary>
        /// aud
        /// </summary>
        Aud,

        /// <summary>
        /// iat
        /// </summary>
        Iat,

        /// <summary>
        /// iss
        /// </summary>
        Iss,

        /// <summary>
        /// jti
        /// </summary>
        Jti,

        /// <summary>
        /// nbf
        /// </summary>
        Nbf,

        /// <summary>
        /// kid
        /// </summary>
        Kid = JwtHeaderParameters.Kid,

        /// <summary>
        /// alg
        /// </summary>
        Alg = JwtHeaderParameters.Alg,

        /// <summary>
        /// enc
        /// </summary>
        Enc = JwtHeaderParameters.Enc,

        /// <summary>
        /// cty
        /// </summary>
        Cty = JwtHeaderParameters.Cty,

        /// <summary>
        /// typ
        /// </summary>
        Typ = JwtHeaderParameters.Typ,

        /// <summary>
        /// zip
        /// </summary>
        Zip = JwtHeaderParameters.Zip,

        /// <summary>
        /// sub
        /// </summary>
        Sub
    }
}