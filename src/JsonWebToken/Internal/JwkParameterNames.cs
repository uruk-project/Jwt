// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Text;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Names for Json Web Key Values
    /// </summary>
    internal static class JwkParameterNames
    {
        public const string Alg = "alg";
        public const string Crv = "crv";
        public static readonly byte[] CrvUtf8 = Encoding.UTF8.GetBytes(Crv);

        public const string D = "d";
        public static readonly byte[] DUtf8 = Encoding.UTF8.GetBytes(D);

        public const string DP = "dp";
        public const string DQ = "dq";
        public const string E = "e";
        public const string K = "k";
        public const string KeyOps = "key_ops";
        public const string Keys = "keys";
        public const string Kid = "kid";
        public const string Kty = "kty";
        public const string N = "n";
        public const string Oth = "oth";
        public const string P = "p";
        public const string Q = "q";
        public const string R = "r";
        public const string T = "t";
        public const string QI = "qi";
        public const string Use = "use";
        public const string X5c = "x5c";
        public const string X5t = "x5t";
        public const string X5tS256 = "x5t#S256";
        public const string X5u = "x5u";
        public const string X = "x";
        public static readonly byte[] XUtf8 = Encoding.UTF8.GetBytes(X);
        public const string Y = "y";
        public static readonly byte[] YUtf8 = Encoding.UTF8.GetBytes(Y);
    }
}
