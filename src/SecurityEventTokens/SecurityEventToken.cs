// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    public sealed class SecurityEventToken : JwtOld
    {
        private JwtObject? _events;

        public SecurityEventToken(JwtOld token)
            : base(token)
        {
        }

        public JwtObject Events
        {
            get
            {
                if (_events is null)
                {
                    if (Payload is null)
                    {
                        return new JwtObject();
                    }

                    if (!Payload.TryGetValue(SetClaims.EventsUtf8, out var events))
                    {
                        return new JwtObject();
                    }

                    _events = (JwtObject?)events.Value;

                    if (_events is null)
                    {
                        return new JwtObject();
                    }
                }

                return _events;
            }
        }

        public DateTime? TimeOfEvent
        {
            get
            {
                if (Payload is null)
                {
                    return null;
                }

                return Payload.TryGetValue(SetClaims.ToeUtf8, out var property) ? EpochTime.ToDateTime((long?)property.Value) : null;
            }
        }

        public string? TransactionNumber
        {
            get
            {
                if (Payload is null)
                {
                    return null;
                }

                return Payload.TryGetValue(SetClaims.TxnUtf8, out var property) ? (string?)property.Value : null;
            }
        }
    }
}