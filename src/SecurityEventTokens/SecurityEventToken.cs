// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;

namespace JsonWebToken
{
    public class SecurityEventToken : Jwt
    {
        private readonly Jwt _token;
        private JwtObject _events;

        public SecurityEventToken(Jwt token)
        {
            _token = token ?? throw new ArgumentNullException(nameof(token));
        }

        public override JwtHeader Header => _token.Header;

        public override JwtPayload Payload => _token.Payload;

        public JwtObject Events
        {
            get
            {
                if (_events == null)
                {
                    if (Payload == null)
                    {
                        return new JwtObject();
                    }

                    if (!Payload.TryGetValue(SetClaims.Events, out var events))
                    {
                        return new JwtObject();
                    }

                    _events = (JwtObject)events.Value;
                    return _events;
                }

                return _events;
            }
        }

        public DateTime? TimeOfEvent
        {
            get
            {
                return Payload.TryGetValue(SetClaims.ToeUtf8.Span, out var property) ? EpochTime.ToDateTime((long?)property.Value) : null;
            }
        }

        public string TransactionNumber
        {
            get
            {
                return Payload.GetValue<string>(SetClaims.Txn);
            }
        }
    }
}