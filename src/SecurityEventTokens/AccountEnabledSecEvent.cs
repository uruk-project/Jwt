// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    public sealed class AccountEnabledSecEvent : SecEvent
    {
        private static readonly JsonEncodedText _name = JsonEncodedText.Encode("https://schemas.openid.net/secevent/risc/event-type/account-enabled", Constants.JsonEncoder);
        public override JsonEncodedText Name => _name;
    }
}
