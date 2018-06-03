using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebTokens
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

                    var events = Payload[ClaimNames.Events] as JObject;
                    _events = events.ToObject<Dictionary<string, JObject>>();
                    return _events;
                }

                return _events;
            }
        }

        public DateTime? TimeOfEvent => ToDateTime(Payload[ClaimNames.Toe]);

        public string TransactionNumber => Payload[ClaimNames.Txn]?.Value<string>();

        private static DateTime? ToDateTime(JToken token)
        {
            if (token == null || token.Type == JTokenType.Null)
            {
                return default;
            }

            return EpochTime.ToDateTime(token.Value<long>());
        }
    }
}