// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Defines an encrypted ID token. <seealso cref="IdTokenDescriptor"/> for signed ID token.</summary>
    public sealed class EncryptedIdTokenDescriptor : JweDescriptorBase<IdTokenDescriptor>
    {
        private IdTokenDescriptor? _payload;

        /// <summary>Initializes a new instance of the <see cref="EncryptedIdTokenDescriptor"/> class.</summary>
        public EncryptedIdTokenDescriptor(SymmetricJwk encryptionKey, SymmetricKeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = null)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
        }
        
        /// <summary>Initializes a new instance of the <see cref="EncryptedIdTokenDescriptor"/> class.</summary>
        public EncryptedIdTokenDescriptor(RsaJwk encryptionKey, RsaKeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = null)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
        }
        
        /// <summary>Initializes a new instance of the <see cref="EncryptedIdTokenDescriptor"/> class.</summary>
        public EncryptedIdTokenDescriptor(ECJwk encryptionKey, ECKeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = null)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
        }

        /// <inheritdoc/>
        public override IdTokenDescriptor Payload
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
