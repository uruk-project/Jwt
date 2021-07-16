// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Defines an encrypted Security Event Token. <seealso cref="SecEventDescriptor"/> for signed Security Event Token.</summary>
    public sealed class EncryptedSecEventDescriptor : JweDescriptorBase<SecEventDescriptor>
    {
        private SecEventDescriptor? _payload;

        /// <summary>Initializes a new instance of the <see cref="EncryptedSecEventDescriptor"/> class.</summary>
        public EncryptedSecEventDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = null)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
        }

        /// <inheritdoc/>
        public override SecEventDescriptor Payload
        {
            get
            {
                if (_payload is null)
                {
                    ThrowHelper.ThrowInvalidOperationException_NotInitialized(ExceptionArgument.payload);
                }

                return _payload;
            }

            set
            {
                if (value is null)
                {
                    ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
                }

                _payload = value;
            }
        }

        /// <inheritdoc/>
        public override void Validate()
        {
            if (_payload != null)
            {
                _payload.Validate();
            }
        }
    }
}
