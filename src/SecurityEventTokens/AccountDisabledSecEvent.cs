// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    public class AccountCredentialChangeRequiredSecEvent : SecEvent
    {
        public override string Name => "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required";
    }

    public class AccountDisabledSecEvent : SecEvent
    {
        public static readonly JsonEncodedText ReasonAttribute = JsonEncodedText.Encode("reason");
        public static readonly JsonEncodedText HijackingReason = JsonEncodedText.Encode("hijacking");
        public static readonly JsonEncodedText BulkAccountReason = JsonEncodedText.Encode("bulk-account");

        public override string Name => "https://schemas.openid.net/secevent/risc/event-type/account-disabled";

        public override void Validate()
        {
            CheckRequiredMemberAsString(ReasonAttribute);
        }
    }

    public class AccountEnabledSecEvent : SecEvent
    {
        public override string Name => "https://schemas.openid.net/secevent/risc/event-type/account-enabled";
    }

    public class AccountPurgedSecEvent : SecEvent
    {
        public override string Name => "https://schemas.openid.net/secevent/risc/event-type/account-purged";
    }
    public class IdentifierChangedSecEvent : SecEvent
    {
        public static readonly JsonEncodedText NewValueAttribute = JsonEncodedText.Encode("new-value");

        public override string Name => "https://schemas.openid.net/secevent/risc/event-type/identifier-changed";

        public override void Validate()
        {
            CheckRequiredMemberAsString(NewValueAttribute);
        }
    }

    public class IdentifierRecycledSecEvent : SecEvent
    {
        public override string Name => "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled";
    }
    public class RecoveryActivatedSecEvent : SecEvent
    {
        public override string Name => "https://schemas.openid.net/secevent/risc/event-type/recovery-activated";
    }
    public class RecoveryInformationChangedSecEvent : SecEvent
    {
        public override string Name => "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed";
    }
    public class SessionsRevokedChangedSecEvent : SecEvent
    {
        public override string Name => "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked";
    }
}
