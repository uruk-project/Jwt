// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    public class AccountDisabledSecEvent : SecEvent
    {
        private static readonly JsonEncodedText _name = JsonEncodedText.Encode("https://schemas.openid.net/secevent/risc/event-type/account-disabled", Constants.JsonEncoder);
        public static readonly JsonEncodedText ReasonAttribute = JsonEncodedText.Encode("reason");
        public static readonly JsonEncodedText HijackingReason = JsonEncodedText.Encode("hijacking");
        public static readonly JsonEncodedText BulkAccountReason = JsonEncodedText.Encode("bulk-account");

        public override JsonEncodedText Name => _name;

        public override void Validate()
        {
            CheckRequiredMemberAsString(ReasonAttribute);
        }
    }
}
