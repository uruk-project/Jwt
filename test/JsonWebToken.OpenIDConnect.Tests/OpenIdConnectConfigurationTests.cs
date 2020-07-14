using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.OpenIDConnect.Tests
{
    public class OpenIdConnectConfigurationTests
    {
        [Theory]
        [MemberData(nameof(GetJson))]
        public void OpenIdConnectConfiguration_Deserialize(string json, OpenIdConnectConfiguration expected)
        {
            var config = OpenIdConnectConfiguration.FromJson(json);

            Assert.Equal(expected.AcrValuesSupported, config.AcrValuesSupported);
            Assert.Equal(expected.AuthorizationEndpoint, config.AuthorizationEndpoint);
            Assert.Equal(expected.CheckSessionIframe, config.CheckSessionIframe);
            Assert.Equal(expected.ClaimsSupported, config.ClaimsSupported);
            Assert.Equal(expected.ClaimsLocalesSupported, config.ClaimsLocalesSupported);
            Assert.Equal(expected.ClaimsParameterSupported, config.ClaimsParameterSupported);
            Assert.Equal(expected.ClaimTypesSupported, config.ClaimTypesSupported);
            Assert.Equal(expected.DisplayValuesSupported, config.DisplayValuesSupported);
            Assert.Equal(expected.EndSessionEndpoint, config.EndSessionEndpoint);
            Assert.Equal(expected.FrontChannelLogoutSessionSupported, config.FrontChannelLogoutSessionSupported);
            Assert.Equal(expected.FrontChannelLogoutSupported, config.FrontChannelLogoutSupported);
            Assert.Equal(expected.GrantTypesSupported, config.GrantTypesSupported);
            Assert.Equal(expected.HttpLogoutSupported, config.HttpLogoutSupported);
            Assert.Equal(expected.IdTokenEncryptionAlgValuesSupported, config.IdTokenEncryptionAlgValuesSupported);
            Assert.Equal(expected.IdTokenEncryptionEncValuesSupported, config.IdTokenEncryptionEncValuesSupported);
            Assert.Equal(expected.IdTokenSigningAlgValuesSupported, config.IdTokenSigningAlgValuesSupported);
            Assert.Equal(expected.Issuer, config.Issuer);
            Assert.Equal(expected.JwksUri, config.JwksUri);
            Assert.Equal(expected.LogoutSessionSupported, config.LogoutSessionSupported);
            Assert.Equal(expected.OpPolicyUri, config.OpPolicyUri);
            Assert.Equal(expected.OpTosUri, config.OpTosUri);
            Assert.Equal(expected.RegistrationEndpoint, config.RegistrationEndpoint);
            Assert.Equal(expected.RequestObjectEncryptionAlgValuesSupported, config.RequestObjectEncryptionAlgValuesSupported);
            Assert.Equal(expected.RequestObjectEncryptionEncValuesSupported, config.RequestObjectEncryptionEncValuesSupported);
            Assert.Equal(expected.RequestObjectSigningAlgValuesSupported, config.RequestObjectSigningAlgValuesSupported);
            Assert.Equal(expected.RequestParameterSupported, config.RequestParameterSupported);
            Assert.Equal(expected.RequestUriParameterSupported, config.RequestUriParameterSupported);
            Assert.Equal(expected.RequireRequestUriRegistration, config.RequireRequestUriRegistration);
            Assert.Equal(expected.ResponseModesSupported, config.ResponseModesSupported);
            Assert.Equal(expected.ResponseTypesSupported, config.ResponseTypesSupported);
            Assert.Equal(expected.ServiceDocumentation, config.ServiceDocumentation);
            Assert.Equal(expected.ScopesSupported, config.ScopesSupported);
            Assert.Equal(expected.SubjectTypesSupported, config.SubjectTypesSupported);
            Assert.Equal(expected.TokenEndpoint, config.TokenEndpoint);
            Assert.Equal(expected.TokenEndpointAuthMethodsSupported, config.TokenEndpointAuthMethodsSupported);
            Assert.Equal(expected.TokenEndpointAuthSigningAlgValuesSupported, config.TokenEndpointAuthSigningAlgValuesSupported);
            Assert.Equal(expected.UILocalesSupported, config.UILocalesSupported);
            Assert.Equal(expected.UserInfoEndpoint, config.UserInfoEndpoint);
            Assert.Equal(expected.UserInfoEncryptionAlgValuesSupported, config.UserInfoEncryptionAlgValuesSupported);
            Assert.Equal(expected.UserInfoEncryptionEncValuesSupported, config.UserInfoEncryptionEncValuesSupported);
            Assert.Equal(expected.UserInfoSigningAlgValuesSupported, config.UserInfoSigningAlgValuesSupported);
            Assert.Equal(expected.RevocationEndpoint, config.RevocationEndpoint);
            Assert.Equal(expected.RevocationEndpointAuthMethodsSupported, config.RevocationEndpointAuthMethodsSupported);
            Assert.Equal(expected.RevocationEndpointAuthSigningAlgValuesSupported, config.RevocationEndpointAuthSigningAlgValuesSupported);
            Assert.Equal(expected.IntrospectionEndpoint, config.IntrospectionEndpoint);
            Assert.Equal(expected.IntrospectionEndpointAuthMethodsSupported, config.IntrospectionEndpointAuthMethodsSupported);
            Assert.Equal(expected.IntrospectionEndpointAuthSigningAlgValuesSupported, config.IntrospectionEndpointAuthSigningAlgValuesSupported);
            Assert.Equal(expected.CodeChallengeMethodsSupported, config.CodeChallengeMethodsSupported);
        }

        public static IEnumerable<object[]> GetJson()
        {
            // https://login.salesforce.com/.well-known/openid-configuration
            yield return new object[] {
                @"{
  ""issuer"": ""https://login.salesforce.com"",
  ""authorization_endpoint"": ""https://login.salesforce.com/services/oauth2/authorize"",
  ""token_endpoint"": ""https://login.salesforce.com/services/oauth2/token"",
  ""revocation_endpoint"": ""https://login.salesforce.com/services/oauth2/revoke"",
  ""userinfo_endpoint"": ""https://login.salesforce.com/services/oauth2/userinfo"",
  ""jwks_uri"": ""https://login.salesforce.com/id/keys"",
  ""register_endpoint"": ""https://login.salesforce.com/services/oauth2/register"",
  ""introspection_endpoint"": ""https://login.salesforce.com/services/oauth2/introspect"",
  ""scopes_supported"": [
    ""id"",
    ""api"",
    ""web"",
    ""full"",
    ""chatter_api"",
    ""visualforce"",
    ""refresh_token"",
    ""openid"",
    ""profile"",
    ""email"",
    ""address"",
    ""phone"",
    ""offline_access"",
    ""custom_permissions"",
    ""wave_api"",
    ""eclair_api""
  ],
  ""response_types_supported"": [
    ""code"",
    ""token"",
    ""token id_token""
  ],
  ""subject_types_supported"": [
    ""public""
  ],
  ""id_token_signing_alg_values_supported"": [
    ""RS256""
  ],
  ""display_values_supported"": [
    ""page"",
    ""popup"",
    ""touch""
  ],
  ""token_endpoint_auth_methods_supported"": [
    ""client_secret_post"",
    ""client_secret_basic"",
    ""private_key_jwt""
  ],
  ""claims_supported"": [
    ""active"",
    ""address"",
    ""email"",
    ""email_verified"",
    ""family_name"",
    ""given_name"",
    ""is_app_installed"",
    ""language"",
    ""locale"",
    ""name"",
    ""nickname"",
    ""organization_id"",
    ""phone_number"",
    ""phone_number_verified"",
    ""photos"",
    ""picture"",
    ""preferred_username"",
    ""profile"",
    ""sub"",
    ""updated_at"",
    ""urls"",
    ""user_id"",
    ""user_type"",
    ""zoneinfo""
  ]
    }",
                new OpenIdConnectConfiguration(
                        "https://login.salesforce.com",
                        "https://login.salesforce.com/services/oauth2/authorize",
                        "https://login.salesforce.com/id/keys", new []  {
                            "code",
                            "token",
                            "token id_token"
                        },
                        new [] { "RS256" }
                    )
                {
                    TokenEndpoint = "https://login.salesforce.com/services/oauth2/token",
                    RevocationEndpoint = "https://login.salesforce.com/services/oauth2/revoke",
                    UserInfoEndpoint ="https://login.salesforce.com/services/oauth2/userinfo",
                    IntrospectionEndpoint= "https://login.salesforce.com/services/oauth2/introspect",
                    ScopesSupported =
                    {
                        "id",
                        "api",
                        "web",
                        "full",
                        "chatter_api",
                        "visualforce",
                        "refresh_token",
                        "openid",
                        "profile",
                        "email",
                        "address",
                        "phone",
                        "offline_access",
                        "custom_permissions",
                        "wave_api",
                        "eclair_api"
                    },
                    SubjectTypesSupported = { "public" },
                    DisplayValuesSupported =
                    {
                        "page",
                        "popup",
                        "touch"
                    },
                    TokenEndpointAuthMethodsSupported =
                    {
                         "client_secret_post",
                        "client_secret_basic",
                        "private_key_jwt"
                    },
                    ClaimsSupported =
                    {
                        "active",
                        "address",
                        "email",
                        "email_verified",
                        "family_name",
                        "given_name",
                        "is_app_installed",
                        "language",
                        "locale",
                        "name",
                        "nickname",
                        "organization_id",
                        "phone_number",
                        "phone_number_verified",
                        "photos",
                        "picture",
                        "preferred_username",
                        "profile",
                        "sub",
                        "updated_at",
                        "urls",
                        "user_id",
                        "user_type",
                        "zoneinfo"
                    }
                }
            };

            // https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
            yield return new object[] {
                @"{
""authorization_endpoint"": ""https://login.microsoftonline.com/common/oauth2/v2.0/authorize"",
""token_endpoint"": ""https://login.microsoftonline.com/common/oauth2/v2.0/token"",
""token_endpoint_auth_methods_supported"": [
""client_secret_post"",
""private_key_jwt"",
""client_secret_basic""
],
""jwks_uri"": ""https://login.microsoftonline.com/common/discovery/v2.0/keys"",
""response_modes_supported"": [
""query"",
""fragment"",
""form_post""
],
""subject_types_supported"": [
""pairwise""
],
""id_token_signing_alg_values_supported"": [
""RS256""
],
""http_logout_supported"": true,
""frontchannel_logout_supported"": true,
""end_session_endpoint"": ""https://login.microsoftonline.com/common/oauth2/v2.0/logout"",
""response_types_supported"": [
""code"",
""id_token"",
""code id_token"",
""id_token token""
],
""scopes_supported"": [
""openid"",
""profile"",
""email"",
""offline_access""
],
""issuer"": ""https://login.microsoftonline.com/{tenantid}/v2.0"",
""claims_supported"": [
""sub"",
""iss"",
""cloud_instance_name"",
""cloud_instance_host_name"",
""cloud_graph_host_name"",
""msgraph_host"",
""aud"",
""exp"",
""iat"",
""auth_time"",
""acr"",
""nonce"",
""preferred_username"",
""name"",
""tid"",
""ver"",
""at_hash"",
""c_hash"",
""email""
],
""request_uri_parameter_supported"": false,
""userinfo_endpoint"": ""https://graph.microsoft.com/oidc/userinfo"",
""tenant_region_scope"": null,
""cloud_instance_name"": ""microsoftonline.com"",
""cloud_graph_host_name"": ""graph.windows.net"",
""msgraph_host"": ""graph.microsoft.com"",
""rbac_url"": ""https://pas.windows.net""
}",
                new OpenIdConnectConfiguration(
                        "https://login.microsoftonline.com/{tenantid}/v2.0",
                        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                        "https://login.microsoftonline.com/common/discovery/v2.0/keys",
                        new []  {
                            "code",
                            "id_token",
                            "code id_token",
                            "id_token token"
                        },
                        new [] { "RS256" }
                    )
                {
                    TokenEndpoint= "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                    TokenEndpointAuthMethodsSupported =
                    {
                        "client_secret_post",
                        "private_key_jwt",
                        "client_secret_basic"
                    },
                    ResponseModesSupported =
                    {
                        "query",
                        "fragment",
                        "form_post"
                    },
                    SubjectTypesSupported=
                    {
                        "pairwise"
                    },
                    HttpLogoutSupported= true,
                    FrontChannelLogoutSupported= true,
                    EndSessionEndpoint= "https://login.microsoftonline.com/common/oauth2/v2.0/logout",

                    ScopesSupported=
                    {
                    "openid",
                    "profile",
                    "email",
                    "offline_access"
                    },
                    ClaimsSupported=
                    {
                    "sub",
                    "iss",
                    "cloud_instance_name",
                    "cloud_instance_host_name",
                    "cloud_graph_host_name",
                    "msgraph_host",
                    "aud",
                    "exp",
                    "iat",
                    "auth_time",
                    "acr",
                    "nonce",
                    "preferred_username",
                    "name",
                    "tid",
                    "ver",
                    "at_hash",
                    "c_hash",
                    "email"
                    },
                    RequestUriParameterSupported = false,
                    UserInfoEndpoint= "https://graph.microsoft.com/oidc/userinfo"
                }
            };

            // https://www.paypalobjects.com/.well-known/openid-configuration
            yield return new object[] {
                @"{
  ""issuer"": ""https://www.paypal.com"",
  ""authorization_endpoint"": ""https://www.paypal.com/signin/authorize"",
  ""token_endpoint"": ""https://api.paypal.com/v1/oauth2/token"",
  ""userinfo_endpoint"": ""https://api.paypal.com/v1/oauth2/token/userinfo"",
  ""jwks_uri"": ""https://api.paypal.com/v1/oauth2/certs"",
  ""token_endpoint_auth_methods_supported"": [
    ""client_secret_basic""
  ],
  ""response_types_supported"": [
    ""code"",
    ""code id_token""
  ],
  ""response_modes_supported"": [
    ""query"",
    ""form_post""
  ],
  ""grant_types_supported"": [
    ""authorization_code"",
    ""refresh_token""
  ],
  ""subject_types_supported"": [
    ""pairwise""
  ],
  ""scopes_supported"": [
    ""email"",
    ""address"",
    ""phone"",
    ""openid"",
    ""profile"",
    ""https://uri.paypal.com/services/wallet/sendmoney"",
    ""https://uri.paypal.com/services/payments/futurepayments"",
    ""https://uri.paypal.com/services/expresscheckout""
  ],
  ""id_token_signing_alg_values_supported"": [
    ""HS256"",
    ""RS256""
  ],
  ""claims_supported"": [
    ""aud"",
    ""iss"",
    ""iat"",
    ""exp"",
    ""auth_time"",
    ""nonce"",
    ""sessionIndex"",
    ""user_id""
  ],
  ""code_challenge_methods_supported"": [
    ""RS256"",
    ""ES256"",
    ""S256""
  ]
    }",
                new OpenIdConnectConfiguration(
                        "https://www.paypal.com",
                        "https://www.paypal.com/signin/authorize",
                        "https://api.paypal.com/v1/oauth2/certs",
                        new [] {
                            "code",
                            "code id_token"
                        },
                        new [] {
                            "HS256",
                            "RS256"
                        }
                    )
                {
                    TokenEndpoint= "https://api.paypal.com/v1/oauth2/token",
                    UserInfoEndpoint= "https://api.paypal.com/v1/oauth2/token/userinfo",
                    TokenEndpointAuthMethodsSupported= {
                        "client_secret_basic"
                    },
                    ResponseModesSupported= {
                        "query",
                        "form_post"
                    },
                    GrantTypesSupported = {
                        "authorization_code",
                        "refresh_token"
                    },
                    SubjectTypesSupported = {
                        "pairwise"
                    },
                    ScopesSupported = {
                        "email",
                        "address",
                        "phone",
                        "openid",
                        "profile",
                        "https://uri.paypal.com/services/wallet/sendmoney",
                        "https://uri.paypal.com/services/payments/futurepayments",
                        "https://uri.paypal.com/services/expresscheckout"
                    },
                    ClaimsSupported = {
                        "aud",
                        "iss",
                        "iat",
                        "exp",
                        "auth_time",
                        "nonce",
                        "sessionIndex",
                        "user_id"
                    },
                    CodeChallengeMethodsSupported= {
                        "RS256",
                        "ES256",
                        "S256"
                    }
                }
            };

            // https://accounts.google.com/.well-known/openid-configuration
            yield return new object[] {
                @"{
 ""issuer"": ""https://accounts.google.com"",
 ""authorization_endpoint"": ""https://accounts.google.com/o/oauth2/v2/auth"",
 ""token_endpoint"": ""https://oauth2.googleapis.com/token"",
 ""userinfo_endpoint"": ""https://openidconnect.googleapis.com/v1/userinfo"",
 ""revocation_endpoint"": ""https://oauth2.googleapis.com/revoke"",
 ""jwks_uri"": ""https://www.googleapis.com/oauth2/v3/certs"",
 ""response_types_supported"": [
  ""code"",
  ""token"",
  ""id_token"",
  ""code token"",
  ""code id_token"",
  ""token id_token"",
  ""code token id_token"",
  ""none""
 ],
 ""subject_types_supported"": [
  ""public""
 ],
 ""id_token_signing_alg_values_supported"": [
  ""RS256""
 ],
 ""scopes_supported"": [
  ""openid"",
  ""email"",
  ""profile""
 ],
 ""token_endpoint_auth_methods_supported"": [
  ""client_secret_post"",
  ""client_secret_basic""
 ],
 ""claims_supported"": [
  ""aud"",
  ""email"",
  ""email_verified"",
  ""exp"",
  ""family_name"",
  ""given_name"",
  ""iat"",
  ""iss"",
  ""locale"",
  ""name"",
  ""picture"",
  ""sub""
 ],
 ""code_challenge_methods_supported"": [
  ""plain"",
  ""S256""
 ]
    }",
                new OpenIdConnectConfiguration(
                        "https://accounts.google.com",
                        "https://accounts.google.com/o/oauth2/v2/auth",
                        "https://www.googleapis.com/oauth2/v3/certs",
                        new [] {
                            "code",
                            "token",
                            "id_token",
                            "code token",
                            "code id_token",
                            "token id_token",
                            "code token id_token",
                            "none"
                        },
                        new[] { "RS256" }
                    )
                {
                    TokenEndpoint = "https://oauth2.googleapis.com/token",
                    UserInfoEndpoint= "https://openidconnect.googleapis.com/v1/userinfo",
                    RevocationEndpoint= "https://oauth2.googleapis.com/revoke",
                    SubjectTypesSupported= {
                        "public"
                    },
                    ScopesSupported= {
                        "openid",
                        "email",
                        "profile"
                    },
                    TokenEndpointAuthMethodsSupported= {
                        "client_secret_post",
                        "client_secret_basic"
                    },
                    ClaimsSupported= {
                        "aud",
                        "email",
                        "email_verified",
                        "exp",
                        "family_name",
                        "given_name",
                        "iat",
                        "iss",
                        "locale",
                        "name",
                        "picture",
                        "sub"
                    },
                    CodeChallengeMethodsSupported= {
                        "plain",
                        "S256"
                    }
                }
            };
        }
    }
}
