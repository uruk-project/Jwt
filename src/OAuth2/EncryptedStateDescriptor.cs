// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Defines an encrypted JWT asstate with a <see cref="StateDescriptor"/> payload.</summary>
    public sealed class EncryptedStateDescriptor : JweDescriptorBase<StateDescriptor>
    {
        private StateDescriptor? _payload;

        /// <summary>Initializes a new instance of the <see cref="EncryptedStateDescriptor"/> class.</summary>
        public EncryptedStateDescriptor(SymmetricJwk encryptionKey, SymmetricKeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null)
            : base(encryptionKey, alg, enc, zip)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="EncryptedStateDescriptor"/> class.</summary>
        public EncryptedStateDescriptor(RsaJwk encryptionKey, RsaKeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null)
            : base(encryptionKey, alg, enc, zip)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="EncryptedStateDescriptor"/> class.</summary>
        public EncryptedStateDescriptor(ECJwk encryptionKey, ECKeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null)
            : base(encryptionKey, alg, enc, zip)
        {
        }

        /// <inheritdoc/>
        public override StateDescriptor Payload
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
            Payload.Validate();
        }
    }
}
