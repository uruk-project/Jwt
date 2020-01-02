// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    public sealed class EncryptedStatedDescriptor : JweDescriptor<StateDescriptor>
    {
        public EncryptedStatedDescriptor()
        {
        }

        public EncryptedStatedDescriptor(StateDescriptor payload) : base(payload)
        {
        }

        public EncryptedStatedDescriptor(JwtObject header, StateDescriptor payload) 
            : base(header, payload)
        {
        }
    }
}
