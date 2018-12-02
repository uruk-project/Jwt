// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Collections.Generic;

namespace JsonWebToken
{
    public class EncryptedStatedDescriptor : JweDescriptor<StateDescriptor>
    {
        public EncryptedStatedDescriptor()
        {
        }

        public EncryptedStatedDescriptor(StateDescriptor payload) : base(payload)
        {
        }

        public EncryptedStatedDescriptor(IDictionary<string, object> header, StateDescriptor payload) : base(header, payload)
        {
        }
    }
}
