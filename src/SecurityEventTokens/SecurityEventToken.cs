// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    public sealed class SecurityEventToken : Jwt
    {
        public SecurityEventToken(Jwt token)
            : base(token)
        {
        }

        public JwtElement Events
        {
            get
            {
                if (!(Payload is null) && Payload.TryGetClaim(SetClaims.EventsUtf8, out var events))
                {
                    return events;
                }

                return default;
            }
        }

        public long? Toe
        {
            get
            {
                if (!(Payload is null) && Payload.TryGetClaim(SetClaims.ToeUtf8, out var value))
                {
                    return value.GetInt64();
                }

                return default;
            }
        }

        public string? Txn
        {
            get
            {
                if (!(Payload is null) && Payload.TryGetClaim(SetClaims.TxnUtf8, out var value))
                {
                    return value.GetString();
                }

                return default;
            }
        }
    }
}