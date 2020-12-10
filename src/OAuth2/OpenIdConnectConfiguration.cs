// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
    public sealed class OpenIdConnectConfiguration
    {
        /// <summary>
        /// Initializes an new instance of <see cref="OpenIdConnectConfiguration"/>.
        /// </summary>
        public OpenIdConnectConfiguration()
        {
            AuthorizationEndpoint = string.Empty;
            Issuer = string.Empty;
            JwksUri = string.Empty;
        }

        /// <summary>
        /// Initializes an new instance of <see cref="OpenIdConnectConfiguration"/>.
        /// </summary>
        public OpenIdConnectConfiguration(
            string issuer,
            string authorizationEndpoint,
            string jwksUri,
            ICollection<string>responseTypesSupported,
            ICollection<string>idTokenSigningAlgValuesSupported)
        {
            Issuer = issuer;
            AuthorizationEndpoint = authorizationEndpoint;
            JwksUri = jwksUri;
            ResponseTypesSupported = responseTypesSupported;
            IdTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
        }

        public static OpenIdConnectConfiguration FromJson(string json)
        {
            if (string.IsNullOrEmpty(json))
            {
                throw new ArgumentNullException(nameof(json));
            }

            return FromJson(Encoding.UTF8.GetBytes(json));
        }

        public static OpenIdConnectConfiguration FromJson(ReadOnlySpan<byte> json)
        {
            var config = JsonSerializer.Deserialize<OpenIdConnectConfiguration>(json, JsonSerializationBehavior.SerializerOptions);
            if (config is null)
            {
                ThrowHelper.ThrowFormatException_MalformedJson();
                return null;
            }

            return config;
        }

        /// <summary>
        /// When deserializing from JSON any properties that are not defined will be placed here.
        /// </summary>
        public Dictionary<string, object> AdditionalData { get; } = new Dictionary<string, object>();

        /// <summary>
        /// Gets the collection of 'acr_values_supported'
        /// </summary>
        public ICollection<string>AcrValuesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'authorization_endpoint'.
        /// </summary>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the 'check_session_iframe'.
        /// </summary>
        public string? CheckSessionIframe { get; set; }

        /// <summary>
        /// Gets the collection of 'claims_supported'
        /// </summary>
        public ICollection<string>ClaimsSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'claims_locales_supported'
        /// </summary>
        public ICollection<string>ClaimsLocalesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'claims_parameter_supported'
        /// </summary>
        public bool? ClaimsParameterSupported { get; set; }

        /// <summary>
        /// Gets the collection of 'claim_types_supported'
        /// </summary>
        public ICollection<string>ClaimTypesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'display_values_supported'
        /// </summary>
        public ICollection<string>DisplayValuesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'end_session_endpoint'.
        /// </summary>
        public string? EndSessionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the 'frontchannel_logout_session_supported'.
        /// </summary>
        public bool? FrontchannelLogoutSessionSupported { get; set; }

        /// <summary>
        /// Gets or sets the 'frontchannel_logout_supported'.
        /// </summary>
        public bool? FrontchannelLogoutSupported { get; set; }

        /// <summary>
        /// Gets the collection of 'grant_types_supported'
        /// </summary>
        public ICollection<string>GrantTypesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Boolean value specifying whether the OP supports HTTP-based logout. Default is false.
        /// </summary>
        public bool? HttpLogoutSupported { get; set; }

        /// <summary>
        /// Gets the collection of 'id_token_encryption_alg_values_supported'.
        /// </summary>
        public ICollection<string>IdTokenEncryptionAlgValuesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'id_token_encryption_enc_values_supported'.
        /// </summary>
        public ICollection<string>IdTokenEncryptionEncValuesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'id_token_signing_alg_values_supported'.
        /// </summary>
        public ICollection<string>IdTokenSigningAlgValuesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'issuer'.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the 'jwks_uri'
        /// </summary>
        public string JwksUri { get; set; }

        /// <summary>
        /// Boolean value specifying whether the OP can pass a sid (session ID) query parameter to identify the RP session at the OP when the logout_uri is used. Dafault Value is false.
        /// </summary>
        public bool? LogoutSessionSupported { get; set; }

        /// <summary>
        /// Gets or sets the 'op_policy_uri'
        /// </summary>
        public string? OpPolicyUri { get; set; }

        /// <summary>
        /// Gets or sets the 'op_tos_uri'
        /// </summary>
        public string? OpTosUri { get; set; }

        /// <summary>
        /// Gets or sets the 'registration_endpoint'
        /// </summary>
        public string? RegistrationEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'request_object_encryption_alg_values_supported'.
        /// </summary>
        public ICollection<string>RequestObjectEncryptionAlgValuesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'request_object_encryption_enc_values_supported'.
        /// </summary>
        public ICollection<string>RequestObjectEncryptionEncValuesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'request_object_signing_alg_values_supported'.
        /// </summary>
        public ICollection<string>RequestObjectSigningAlgValuesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'request_parameter_supported'
        /// </summary>
        public bool? RequestParameterSupported { get; set; }

        /// <summary>
        /// Gets or sets the 'request_uri_parameter_supported'
        /// </summary>
        public bool? RequestUriParameterSupported { get; set; }

        /// <summary>
        /// Gets or sets the 'require_request_uri_registration'
        /// </summary>
        public bool? RequireRequestUriRegistration { get; set; }

        /// <summary>
        /// Gets the collection of 'response_modes_supported'.
        /// </summary>
        public ICollection<string>ResponseModesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'response_types_supported'.
        /// </summary>
        public ICollection<string>ResponseTypesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'service_documentation'
        /// </summary>
        public string? ServiceDocumentation { get; set; }

        /// <summary>
        /// Gets the collection of 'scopes_supported'
        /// </summary>
        public ICollection<string>ScopesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'subject_types_supported'.
        /// </summary>
        public ICollection<string>SubjectTypesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'token_endpoint'.
        /// </summary>
        public string? TokenEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'token_endpoint_auth_methods_supported'.
        /// </summary>
        public ICollection<string>TokenEndpointAuthMethodsSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'token_endpoint_auth_signing_alg_values_supported'.
        /// </summary>
        public ICollection<string>TokenEndpointAuthSigningAlgValuesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'ui_locales_supported'
        /// </summary>
        public ICollection<string>UILocalesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'user_info_endpoint'.
        /// </summary>
        public string? UserinfoEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'userinfo_encryption_alg_values_supported'
        /// </summary>
        public ICollection<string>UserinfoEncryptionAlgValuesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'userinfo_encryption_enc_values_supported'
        /// </summary>
        public ICollection<string>UserinfoEncryptionEncValuesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'userinfo_signing_alg_values_supported'
        /// </summary>
        public ICollection<string>UserinfoSigningAlgValuesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'revocation_endpoint'.
        /// </summary>
        public string? RevocationEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'revocation_endpoint_auth_methods_supported'
        /// </summary>
        public ICollection<string>RevocationEndpointAuthMethodsSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'revocation_endpoint_auth_signing_alg_values_supported'
        /// </summary>
        public ICollection<string>RevocationEndpointAuthSigningAlgValuesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'introspection_endpoint'.
        /// </summary>
        public string? IntrospectionEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'introspection_endpoint_auth_methods_supported'
        /// </summary>
        public ICollection<string>IntrospectionEndpointAuthMethodsSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'introspection_endpoint_auth_signing_alg_values_supported'
        /// </summary>
        public ICollection<string>IntrospectionEndpointAuthSigningAlgValuesSupported { get; set; } = new List<string>();

        /// <summary>
        /// Gets the collection of 'code_challenge_methods_supported'
        /// </summary>
        public ICollection<string>CodeChallengeMethodsSupported { get; set; } = new List<string>();
    }
}
