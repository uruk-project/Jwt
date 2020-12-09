// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    public sealed class EmailSubjectIdentifier : ISubjectIdentifier
    {
        public string SubjectType => "email";

        public EmailSubjectIdentifier(string email)
        {
            Email = email ?? throw new ArgumentNullException(nameof(email));
        }

        public string Email { get; }
    }
}
