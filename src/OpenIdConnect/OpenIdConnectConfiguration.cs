// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;
using System.Text.Json;

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
            Utf8JsonReader reader = new Utf8JsonReader(json, true, default);
            if (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
            {
                var config = new OpenIdConnectConfiguration();
                while (reader.Read())
                {
                    switch (reader.TokenType)
                    {
                        case JsonTokenType.EndObject:
                            return config;

                        case JsonTokenType.PropertyName:
                            var propertyName = reader.GetString();

                            reader.Read();
                            switch (reader.TokenType)
                            {
                                case JsonTokenType.True:
                                    switch (propertyName)
                                    {
                                        case OpenIdProviderMetadataNames.ClaimsParameterSupported:
                                            config.ClaimsParameterSupported = true;
                                            break;
                                        case OpenIdProviderMetadataNames.FrontChannelLogoutSessionSupported:
                                            config.FrontChannelLogoutSessionSupported = true;
                                            break;
                                        case OpenIdProviderMetadataNames.FrontChannelLogoutSupported:
                                            config.FrontChannelLogoutSupported = true;
                                            break;
                                        case OpenIdProviderMetadataNames.HttpLogoutSupported:
                                            config.HttpLogoutSupported = true;
                                            break;
                                        case OpenIdProviderMetadataNames.LogoutSessionSupported:
                                            config.LogoutSessionSupported = true;
                                            break;
                                        case OpenIdProviderMetadataNames.RequestParameterSupported:
                                            config.RequestParameterSupported = true;
                                            break;
                                        case OpenIdProviderMetadataNames.RequestUriParameterSupported:
                                            config.RequestUriParameterSupported = true;
                                            break;
                                        case OpenIdProviderMetadataNames.RequireRequestUriRegistration:
                                            config.RequireRequestUriRegistration = true;
                                            break;

                                        default:
                                            config.AdditionalData.Add(new JwtProperty(Encoding.UTF8.GetBytes(propertyName), true));
                                            break;
                                    }
                                    break;
                                case JsonTokenType.False:
                                    switch (propertyName)
                                    {
                                        case OpenIdProviderMetadataNames.ClaimsParameterSupported:
                                            config.ClaimsParameterSupported = false;
                                            break;
                                        case OpenIdProviderMetadataNames.FrontChannelLogoutSessionSupported:
                                            config.FrontChannelLogoutSessionSupported = false;
                                            break;
                                        case OpenIdProviderMetadataNames.FrontChannelLogoutSupported:
                                            config.FrontChannelLogoutSupported = false;
                                            break;
                                        case OpenIdProviderMetadataNames.HttpLogoutSupported:
                                            config.HttpLogoutSupported = false;
                                            break;
                                        case OpenIdProviderMetadataNames.LogoutSessionSupported:
                                            config.LogoutSessionSupported = false;
                                            break;
                                        case OpenIdProviderMetadataNames.RequestParameterSupported:
                                            config.RequestParameterSupported = false;
                                            break;
                                        case OpenIdProviderMetadataNames.RequestUriParameterSupported:
                                            config.RequestUriParameterSupported = false;
                                            break;
                                        case OpenIdProviderMetadataNames.RequireRequestUriRegistration:
                                            config.RequireRequestUriRegistration = false;
                                            break;
                                        default:
                                            config.AdditionalData.Add(new JwtProperty(Encoding.UTF8.GetBytes(propertyName), false));
                                            break;
                                    }
                                    break;
                                case JsonTokenType.String:
                                    switch (propertyName)
                                    {
                                        case OpenIdProviderMetadataNames.AuthorizationEndpoint:
                                            config.AuthorizationEndpoint = reader.GetString();
                                            break;
                                        case OpenIdProviderMetadataNames.CheckSessionIframe:
                                            config.CheckSessionIframe = reader.GetString();
                                            break;
                                        case OpenIdProviderMetadataNames.EndSessionEndpoint:
                                            config.EndSessionEndpoint = reader.GetString();
                                            break;
                                        case OpenIdProviderMetadataNames.Issuer:
                                            config.Issuer = reader.GetString();
                                            break;
                                        case OpenIdProviderMetadataNames.JwksUri:
                                            config.JwksUri = reader.GetString();
                                            break;
                                        case OpenIdProviderMetadataNames.OpPolicyUri:
                                            config.OpPolicyUri = reader.GetString();
                                            break;
                                        case OpenIdProviderMetadataNames.OpTosUri:
                                            config.OpTosUri = reader.GetString();
                                            break;
                                        case OpenIdProviderMetadataNames.RegistrationEndpoint:
                                            config.RegistrationEndpoint = reader.GetString();
                                            break;
                                        case OpenIdProviderMetadataNames.ServiceDocumentation:
                                            config.ServiceDocumentation = reader.GetString();
                                            break;
                                        case OpenIdProviderMetadataNames.TokenEndpoint:
                                            config.TokenEndpoint = reader.GetString();
                                            break;
                                        case OpenIdProviderMetadataNames.UserInfoEndpoint:
                                            config.UserInfoEndpoint = reader.GetString();
                                            break;
                                        case OpenIdProviderMetadataNames.RevocationEndpoint:
                                            config.RevocationEndpoint = reader.GetString();
                                            break;
                                        case OpenIdProviderMetadataNames.IntrospectionEndpoint:
                                            config.IntrospectionEndpoint = reader.GetString();
                                            break;
                                        default:
                                            config.AdditionalData.Add(new JwtProperty(Encoding.UTF8.GetBytes(propertyName), reader.GetString()));
                                            break;
                                    }
                                    break;

                                case JsonTokenType.StartArray:
                                    switch (propertyName)
                                    {
                                        case OpenIdProviderMetadataNames.AcrValuesSupported:
                                            config.AcrValuesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.ClaimsSupported:
                                            config.ClaimsSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.ClaimsLocalesSupported:
                                            config.ClaimsLocalesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.ClaimTypesSupported:
                                            config.ClaimTypesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.DisplayValuesSupported:
                                            config.DisplayValuesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.GrantTypesSupported:
                                            config.GrantTypesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.IdTokenEncryptionAlgValuesSupported:
                                            config.IdTokenEncryptionAlgValuesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.IdTokenEncryptionEncValuesSupported:
                                            config.IdTokenEncryptionEncValuesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.IdTokenSigningAlgValuesSupported:
                                            config.IdTokenSigningAlgValuesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.RequestObjectEncryptionAlgValuesSupported:
                                            config.RequestObjectEncryptionAlgValuesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.RequestObjectEncryptionEncValuesSupported:
                                            config.RequestObjectEncryptionEncValuesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.RequestObjectSigningAlgValuesSupported:
                                            config.RequestObjectSigningAlgValuesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.ResponseModesSupported:
                                            config.ResponseModesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.ResponseTypesSupported:
                                            config.ResponseTypesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.ScopesSupported:
                                            config.ScopesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.SubjectTypesSupported:
                                            config.SubjectTypesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.TokenEndpointAuthMethodsSupported:
                                            config.TokenEndpointAuthMethodsSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.TokenEndpointAuthSigningAlgValuesSupported:
                                            config.TokenEndpointAuthSigningAlgValuesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.UILocalesSupported:
                                            config.UILocalesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.UserInfoEncryptionAlgValuesSupported:
                                            config.UserInfoEncryptionAlgValuesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.UserInfoEncryptionEncValuesSupported:
                                            config.UserInfoEncryptionEncValuesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.UserInfoSigningAlgValuesSupported:
                                            config.UserInfoSigningAlgValuesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.RevocationEndpointAuthMethodsSupported:
                                            config.RevocationEndpointAuthMethodsSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.RevocationEndpointAuthSigningAlgValuesSupported:
                                            config.RevocationEndpointAuthSigningAlgValuesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.IntrospectionEndpointAuthMethodsSupported:
                                            config.IntrospectionEndpointAuthMethodsSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.IntrospectionEndpointAuthSigningAlgValuesSupported:
                                            config.IntrospectionEndpointAuthSigningAlgValuesSupported = GetStringArray(ref reader);
                                            break;
                                        case OpenIdProviderMetadataNames.CodeChallengeMethodsSupported:
                                            config.CodeChallengeMethodsSupported = GetStringArray(ref reader);
                                            break;
                                        default:
                                            config.AdditionalData.Add(new JwtProperty(Encoding.UTF8.GetBytes(propertyName), JsonParser.ReadJsonArray(ref reader)));
                                            break;
                                    }
                                    break;
                                case JsonTokenType.StartObject:
                                    config.AdditionalData.Add(new JwtProperty(Encoding.UTF8.GetBytes(propertyName), JsonParser.ReadJsonObject(ref reader)));
                                    break;
                                case JsonTokenType.Number:
                                    if (reader.TryGetInt64(out long longValue))
                                    {
                                        config.AdditionalData.Add(new JwtProperty(Encoding.UTF8.GetBytes(propertyName), longValue));
                                    }
                                    else if (reader.TryGetDouble(out double doubleValue))
                                    {
                                        config.AdditionalData.Add(new JwtProperty(Encoding.UTF8.GetBytes(propertyName), doubleValue));
                                    }
                                    break;
                            }
                            break;
                        default:
                            JwtThrowHelper.FormatMalformedJson();
                            break;
                    }
                }
            }

            JwtThrowHelper.FormatMalformedJson();
            return null;
        }

        private static ICollection<string> GetStringArray(ref Utf8JsonReader reader)
        {
            var list = new List<string>();
            while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
            {
                list.Add(reader.GetString());
            }

            return list;
        }


        /// <summary>
        /// When deserializing from JSON any properties that are not defined will be placed here.
        /// </summary>
        public virtual JwtObject AdditionalData { get; } = new JwtObject();

        /// <summary>
        /// Gets the collection of 'acr_values_supported'
        /// </summary>
        public ICollection<string> AcrValuesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'authorization_endpoint'.
        /// </summary>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the 'check_session_iframe'.
        /// </summary>
        public string CheckSessionIframe { get; set; }

        /// <summary>
        /// Gets the collection of 'claims_supported'
        /// </summary>
        public ICollection<string> ClaimsSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'claims_locales_supported'
        /// </summary>
        public ICollection<string> ClaimsLocalesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'claims_parameter_supported'
        /// </summary>
        public bool? ClaimsParameterSupported { get; set; }

        /// <summary>
        /// Gets the collection of 'claim_types_supported'
        /// </summary>
        public ICollection<string> ClaimTypesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'display_values_supported'
        /// </summary>
        public ICollection<string> DisplayValuesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'end_session_endpoint'.
        /// </summary>
        public string EndSessionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the 'frontchannel_logout_session_supported'.
        /// </summary>
        public bool? FrontChannelLogoutSessionSupported { get; set; }

        /// <summary>
        /// Gets or sets the 'frontchannel_logout_supported'.
        /// </summary>
        public bool? FrontChannelLogoutSupported { get; set; }

        /// <summary>
        /// Gets the collection of 'grant_types_supported'
        /// </summary>
        public ICollection<string> GrantTypesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Boolean value specifying whether the OP supports HTTP-based logout. Default is false.
        /// </summary>
        public bool? HttpLogoutSupported { get; set; }

        /// <summary>
        /// Gets the collection of 'id_token_encryption_alg_values_supported'.
        /// </summary>
        public ICollection<string> IdTokenEncryptionAlgValuesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'id_token_encryption_enc_values_supported'.
        /// </summary>
        public ICollection<string> IdTokenEncryptionEncValuesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'id_token_signing_alg_values_supported'.
        /// </summary>
        public ICollection<string> IdTokenSigningAlgValuesSupported { get; private set; } = new Collection<string>();

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
        public string OpPolicyUri { get; set; }

        /// <summary>
        /// Gets or sets the 'op_tos_uri'
        /// </summary>
        public string OpTosUri { get; set; }

        /// <summary>
        /// Gets or sets the 'registration_endpoint'
        /// </summary>
        public string RegistrationEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'request_object_encryption_alg_values_supported'.
        /// </summary>
        public ICollection<string> RequestObjectEncryptionAlgValuesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'request_object_encryption_enc_values_supported'.
        /// </summary>
        public ICollection<string> RequestObjectEncryptionEncValuesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'request_object_signing_alg_values_supported'.
        /// </summary>
        public ICollection<string> RequestObjectSigningAlgValuesSupported { get; private set; } = new Collection<string>();

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
        public ICollection<string> ResponseModesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'response_types_supported'.
        /// </summary>
        public ICollection<string> ResponseTypesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'service_documentation'
        /// </summary>
        public string ServiceDocumentation { get; set; }

        /// <summary>
        /// Gets the collection of 'scopes_supported'
        /// </summary>
        public ICollection<string> ScopesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'subject_types_supported'.
        /// </summary>
        public ICollection<string> SubjectTypesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'token_endpoint'.
        /// </summary>
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'token_endpoint_auth_methods_supported'.
        /// </summary>
        public ICollection<string> TokenEndpointAuthMethodsSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'token_endpoint_auth_signing_alg_values_supported'.
        /// </summary>
        public ICollection<string> TokenEndpointAuthSigningAlgValuesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'ui_locales_supported'
        /// </summary>
        public ICollection<string> UILocalesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'user_info_endpoint'.
        /// </summary>
        public string UserInfoEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'userinfo_encryption_alg_values_supported'
        /// </summary>
        public ICollection<string> UserInfoEncryptionAlgValuesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'userinfo_encryption_enc_values_supported'
        /// </summary>
        public ICollection<string> UserInfoEncryptionEncValuesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'userinfo_signing_alg_values_supported'
        /// </summary>
        public ICollection<string> UserInfoSigningAlgValuesSupported { get; private set; } = new Collection<string>();


        /// <summary>
        /// Gets or sets the 'revocation_endpoint'.
        /// </summary>
        public string RevocationEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'revocation_endpoint_auth_methods_supported'
        /// </summary>
        public ICollection<string> RevocationEndpointAuthMethodsSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'revocation_endpoint_auth_signing_alg_values_supported'
        /// </summary>
        public ICollection<string> RevocationEndpointAuthSigningAlgValuesSupported { get; private set; } = new Collection<string>();
        
        /// <summary>
        /// Gets or sets the 'introspection_endpoint'.
        /// </summary>
        public string IntrospectionEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'introspection_endpoint_auth_methods_supported'
        /// </summary>
        public ICollection<string> IntrospectionEndpointAuthMethodsSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'introspection_endpoint_auth_signing_alg_values_supported'
        /// </summary>
        public ICollection<string> IntrospectionEndpointAuthSigningAlgValuesSupported { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'code_challenge_methods_supported'
        /// </summary>
        public ICollection<string> CodeChallengeMethodsSupported { get; private set; } = new Collection<string>();




    }
}
