// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Text;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// List of header parameter names see: http://tools.ietf.org/html/rfc7519#section-5.
    /// </summary>
    public static class HeaderParameters
    {
        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.1
        /// </summary>
        public const string Alg = "alg";
        public static readonly byte[] AlgUtf8 = Encoding.UTF8.GetBytes(Alg);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.10
        /// also:https://tools.ietf.org/html/rfc7519#section-5.2
        /// </summary>
        public const string Cty = "cty";
        public static readonly byte[] CtyUtf8 = Encoding.UTF8.GetBytes(Cty);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.2
        /// </summary>
        public const string Enc = "enc";
        public static readonly byte[] EncUtf8 = Encoding.UTF8.GetBytes(Enc);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.2
        /// </summary>
        public const string Jku = "jku";
        public static readonly byte[] JkuUtf8 = Encoding.UTF8.GetBytes(Jku);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.3
        /// </summary>
        public const string Jwk = "jwk";
        public static readonly byte[] JwkUtf8 = Encoding.UTF8.GetBytes(Jwk);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.4
        /// </summary>
        public const string Kid = "kid";
        public static readonly byte[] KidUtf8 = Encoding.UTF8.GetBytes(Kid);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.9
        /// also:https://tools.ietf.org/html/rfc7519#section-5.1
        /// </summary>
        public const string Typ = "typ";
        public static readonly byte[] TypUtf8 = Encoding.UTF8.GetBytes(Typ);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.6
        /// </summary>
        public const string X5c = "x5c";
        public static readonly byte[] X5cUtf8 = Encoding.UTF8.GetBytes(X5c);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#page-12
        /// </summary>
        public const string X5t = "x5t";
        public static readonly byte[] X5tUtf8 = Encoding.UTF8.GetBytes(X5t);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.5
        /// </summary>
        public const string X5u = "x5u";
        public static readonly byte[] X5uUtf8 = Encoding.UTF8.GetBytes(X5u);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.5
        /// </summary>
        public const string Crit = "crit";
        public static readonly byte[] CritUtf8 = Encoding.UTF8.GetBytes(Crit);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7516#section-4.1.3
        /// </summary>
        public const string Zip = "zip";
        public static readonly byte[] ZipUtf8 = Encoding.UTF8.GetBytes(Zip);

        public const string Address = "address";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.6.1
        /// </summary>
        public const string Epk = "epk";
        public static readonly byte[] EpkUtf8 = Encoding.UTF8.GetBytes(Epk);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.6.1
        /// </summary>
        public const string Apu = "apu";
        public static readonly byte[] ApuUtf8 = Encoding.UTF8.GetBytes(Apu);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.6.1
        /// </summary>
        public const string Apv = "apv";
        public static readonly byte[] ApvUtf8 = Encoding.UTF8.GetBytes(Apv);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.7
        /// </summary>
        public const string IV = "iv";
        public static readonly byte[] IVUtf8 = Encoding.UTF8.GetBytes(IV);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.7
        /// </summary>
        public const string Tag = "tag";
        public static readonly byte[] TagUtf8 = Encoding.UTF8.GetBytes(Tag);

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.8
        /// </summary>
        public const string P2s = "p2s";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7518#section-4.8
        /// </summary>
        public const string P2c = "p2c";
    }
}
