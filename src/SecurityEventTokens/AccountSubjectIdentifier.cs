// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    public sealed class AccountSubjectIdentifier : ISubjectIdentifier
    {
        public string SubjectType => "account";

        public AccountSubjectIdentifier(string account)
        {
            Account = account ?? throw new ArgumentNullException(nameof(account));
        }

        public string Account { get; }
    }
}
