// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Defines an encrypted access token with a <see cref="AccessTokenDescriptor"/> payload.</summary>
    public sealed class EncryptedAccesTokenDescriptor : JweDescriptorBase<AccessTokenDescriptor>
    {
        private AccessTokenDescriptor? _payload;

        /// <summary>Initializes a new instance of the <see cref="EncryptedAccesTokenDescriptor"/> class.</summary>
        public EncryptedAccesTokenDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null)
            : base(encryptionKey, alg, enc, zip)
        {
        }

        /// <inheritdoc/>
        public override AccessTokenDescriptor Payload
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
