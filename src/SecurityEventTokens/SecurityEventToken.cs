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

                    if(!Payload.TryGetValue(ClaimNames.Events, out var events))
                    {
                        return new Dictionary<string, JObject>();
                    }

                    _events = events.ToObject<Dictionary<string, JObject>>();
                    return _events;
                }

                return _events;
            }
        }

        public DateTime? TimeOfEvent
        {
            get
            {
                if (Payload.TryGetValue(ClaimNames.Toe, out var toe))
                {
                    if (toe == null || toe.Type == JTokenType.Null)
                    {
                        return default;
                    }

                    return EpochTime.ToDateTime(toe.Value<long>());
                }

                return null;
            }
        }

        public string TransactionNumber
        {
            get
            {
                if (Payload.TryGetValue(ClaimNames.Txn, out var txn))
                {
                    return txn.Value<string>();
                }

                return null;
            }
        }
    }
}