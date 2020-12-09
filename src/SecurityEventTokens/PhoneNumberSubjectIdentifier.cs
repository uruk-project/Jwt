// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    public sealed class PhoneNumberSubjectIdentifier : ISubjectIdentifier
    {
        public string SubjectType => "phone_number";

        public PhoneNumberSubjectIdentifier(string phoneNumber)
        {
            PhoneNumber = phoneNumber ?? throw new ArgumentNullException(nameof(phoneNumber));
        }

        public string PhoneNumber { get; }
    }
}
