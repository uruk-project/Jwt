// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    public sealed class IssuerAndSubjectSubjectIdentifier : ISubjectIdentifier
    {
        public string SubjectType => "iss_sub";

        public IssuerAndSubjectSubjectIdentifier(string iss, string sub)
        {
            Iss = iss ?? throw new ArgumentNullException(nameof(iss));
            Sub = sub ?? throw new ArgumentNullException(nameof(sub));
        }
        
        public string Iss { get; }

        public string Sub { get;  }
    }
}
