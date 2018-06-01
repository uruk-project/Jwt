using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading;

namespace JsonWebToken
{
    public class OpenIdConnectConfiguration
    {

        /// <summary>
        /// Initializes an new instance of <see cref="OpenIdConnectConfiguration"/>.
        /// </summary>
        public OpenIdConnectConfiguration()
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="OpenIdConnectConfiguration"/> from a json string.
        /// </summary>
        /// <param name="json">a json string containing the metadata</param>
        /// <exception cref="ArgumentNullException">If 'json' is null or empty.</exception>
        public OpenIdConnectConfiguration(string json)
        {
            if (string.IsNullOrEmpty(json))
            {
                throw new ArgumentNullException(nameof(json));
            }

            JsonConvert.PopulateObject(json, this);
        }

        /// <summary>
        /// When deserializing from JSON any properties that are not defined will be placed here.
        /// </summary>
        [JsonExtensionData]
        public virtual IDictionary<string, object> AdditionalData { get; } = new Dictionary<string, object>();

        /// <summary>
        /// Gets the collection of 'acr_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.AcrValuesSupported, Required = Required.Default)]
        public ICollection<string> AcrValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'authorization_endpoint'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.AuthorizationEndpoint, Required = Required.Default)]
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the 'check_session_iframe'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.CheckSessionIframe, Required = Required.Default)]
        public string CheckSessionIframe { get; set; }

        /// <summary>
        /// Gets the collection of 'claims_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ClaimsSupported, Required = Required.Default)]
        public ICollection<string> ClaimsSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'claims_locales_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ClaimsLocalesSupported, Required = Required.Default)]
        public ICollection<string> ClaimsLocalesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'claims_parameter_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ClaimsParameterSupported, Required = Required.Default)]
        public bool ClaimsParameterSupported { get; set; }

        /// <summary>
        /// Gets the collection of 'claim_types_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ClaimTypesSupported, Required = Required.Default)]
        public ICollection<string> ClaimTypesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'display_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.DisplayValuesSupported, Required = Required.Default)]
        public ICollection<string> DisplayValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'end_session_endpoint'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.EndSessionEndpoint, Required = Required.Default)]
        public string EndSessionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the 'frontchannel_logout_session_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.FrontchannelLogoutSessionSupported, Required = Required.Default)]
        public string FrontchannelLogoutSessionSupported { get; set; }

        /// <summary>
        /// Gets or sets the 'frontchannel_logout_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.FrontchannelLogoutSupported, Required = Required.Default)]
        public string FrontchannelLogoutSupported { get; set; }

        /// <summary>
        /// Gets the collection of 'grant_types_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.GrantTypesSupported, Required = Required.Default)]
        public ICollection<string> GrantTypesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Boolean value specifying whether the OP supports HTTP-based logout. Default is false.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.HttpLogoutSupported, Required = Required.Default)]
        public bool HttpLogoutSupported { get; set; }

        /// <summary>
        /// Gets the collection of 'id_token_encryption_alg_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.IdTokenEncryptionAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> IdTokenEncryptionAlgValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'id_token_encryption_enc_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.IdTokenEncryptionEncValuesSupported, Required = Required.Default)]
        public ICollection<string> IdTokenEncryptionEncValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'id_token_signing_alg_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.IdTokenSigningAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> IdTokenSigningAlgValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'issuer'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.Issuer, Required = Required.Default)]
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the 'jwks_uri'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.JwksUri, Required = Required.Default)]
        public string JwksUri { get; set; }

        /// <summary>
        /// Boolean value specifying whether the OP can pass a sid (session ID) query parameter to identify the RP session at the OP when the logout_uri is used. Dafault Value is false.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.LogoutSessionSupported, Required = Required.Default)]
        public bool LogoutSessionSupported { get; set; }

        /// <summary>
        /// Gets or sets the 'op_policy_uri'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.OpPolicyUri, Required = Required.Default)]
        public string OpPolicyUri { get; set; }

        /// <summary>
        /// Gets or sets the 'op_tos_uri'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.OpTosUri, Required = Required.Default)]
        public string OpTosUri { get; set; }

        /// <summary>
        /// Gets or sets the 'registration_endpoint'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RegistrationEndpoint, Required = Required.Default)]
        public string RegistrationEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'request_object_encryption_alg_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RequestObjectEncryptionAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> RequestObjectEncryptionAlgValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'request_object_encryption_enc_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RequestObjectEncryptionEncValuesSupported, Required = Required.Default)]
        public ICollection<string> RequestObjectEncryptionEncValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'request_object_signing_alg_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RequestObjectSigningAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> RequestObjectSigningAlgValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'request_parameter_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RequestParameterSupported, Required = Required.Default)]
        public bool RequestParameterSupported { get; set; }

        /// <summary>
        /// Gets or sets the 'request_uri_parameter_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RequestUriParameterSupported, Required = Required.Default)]
        public bool RequestUriParameterSupported { get; set; }

        /// <summary>
        /// Gets or sets the 'require_request_uri_registration'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RequireRequestUriRegistration, Required = Required.Default)]
        public bool RequireRequestUriRegistration { get; set; }

        /// <summary>
        /// Gets the collection of 'response_modes_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ResponseModesSupported, Required = Required.Default)]
        public ICollection<string> ResponseModesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'response_types_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ResponseTypesSupported, Required = Required.Default)]
        public ICollection<string> ResponseTypesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'service_documentation'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ServiceDocumentation, Required = Required.Default)]
        public string ServiceDocumentation { get; set; }

        /// <summary>
        /// Gets the collection of 'scopes_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ScopesSupported, Required = Required.Default)]
        public ICollection<string> ScopesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'subject_types_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.SubjectTypesSupported, Required = Required.Default)]
        public ICollection<string> SubjectTypesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'token_endpoint'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.TokenEndpoint, Required = Required.Default)]
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'token_endpoint_auth_methods_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.TokenEndpointAuthMethodsSupported, Required = Required.Default)]
        public ICollection<string> TokenEndpointAuthMethodsSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'token_endpoint_auth_signing_alg_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.TokenEndpointAuthSigningAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> TokenEndpointAuthSigningAlgValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'ui_locales_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UILocalesSupported, Required = Required.Default)]
        public ICollection<string> UILocalesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'user_info_endpoint'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UserInfoEndpoint, Required = Required.Default)]
        public string UserInfoEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'userinfo_encryption_alg_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UserInfoEncryptionAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> UserInfoEndpointEncryptionAlgValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'userinfo_encryption_enc_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UserInfoEncryptionEncValuesSupported, Required = Required.Default)]
        public ICollection<string> UserInfoEndpointEncryptionEncValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'userinfo_signing_alg_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UserInfoSigningAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> UserInfoEndpointSigningAlgValuesSupported { get; } = new Collection<string>();
    }
}
