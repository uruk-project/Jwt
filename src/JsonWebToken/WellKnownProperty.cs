// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines the well known JWT properties.
    /// </summary>
    public enum WellKnownProperty : byte
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
        Kid,

        /// <summary>
        /// alg
        /// </summary>
        Alg,

        /// <summary>
        /// enc
        /// </summary>
        Enc,

        /// <summary>
        /// cty
        /// </summary>
        Cty,

        /// <summary>
        /// typ
        /// </summary>
        Typ,

        /// <summary>
        /// zip
        /// </summary>
        Zip,

        /// <summary>
        /// sub
        /// </summary>
        Sub
    }
}