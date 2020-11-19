// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    public class IdentifierChangedSecEvent : SecEvent
    {
        private static readonly JsonEncodedText _name = JsonEncodedText.Encode("https://schemas.openid.net/secevent/risc/event-type/identifier-changed", Constants.JsonEncoder);
        public static readonly JsonEncodedText NewValueAttribute = JsonEncodedText.Encode("new-value");

        public override JsonEncodedText Name => _name;

        public override void Validate()
        {
            CheckRequiredMemberAsString(NewValueAttribute);
        }
    }
}
