// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class SecurityEventToken : JsonWebToken
    {
        private readonly JsonWebToken _token;
        private IReadOnlyDictionary<string, JObject> _events;

        public SecurityEventToken(JsonWebToken token)
        {
            _token = token ?? throw new ArgumentNullException(nameof(token));
        }

        public override JwtHeader Header => _token.Header;

        public override JwtPayload Payload => _token.Payload;

        public IReadOnlyDictionary<string, JObject> Events
        {
            get
            {
                if (_events == null)
                {
                    if (Payload == null)
                    {
                        return new Dictionary<string, JObject>();
                    }

                    if (!Payload.TryGetValue(Claims.Events, out var events))
                    {
                        return new Dictionary<string, JObject>();
                    }

                    _events = JToken.FromObject(events).ToObject<Dictionary<string, JObject>>();
                    return _events;
                }

                return _events;
            }
        }

        public DateTime? TimeOfEvent
        {
            get
            {
                return EpochTime.ToDateTime(Payload.GetValue<long?>(Claims.Toe));
            }
        }

        public string TransactionNumber
        {
            get
            {
                return Payload.GetValue<string>(Claims.Txn);
            }
        }
    }
}