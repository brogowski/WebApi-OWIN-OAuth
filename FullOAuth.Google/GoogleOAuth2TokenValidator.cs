using System;
using FullOAuth.ExternalAuthorization;
using FullOAuth.ExternalAuthorization.Extensions;
using Microsoft.Owin.Security.Google;
using Newtonsoft.Json.Linq;

namespace FullOAuth.Google
{
    class GoogleOAuth2TokenValidator : AbstractExternalTokenValidator
    {
        private const string ProviderName = "Google";
        private const string GoogleTokenValidationUrlFormat = "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={0}";
        private const string UserIdKey = "user_id";
        private const string AppIdKey = "audience";

        private readonly GoogleOAuth2AuthenticationOptions _googleAuthenticationOptions;

        public GoogleOAuth2TokenValidator(GoogleOAuth2AuthenticationOptions authenticationOptions)
        {
            _googleAuthenticationOptions = authenticationOptions;
        }

        protected override ParsedExternalAccessToken ParseExternalToken(JObject jObj)
        {
            dynamic dynamicObj = jObj;

            var parsedToken = new GoogleOAuth2ParsedExternalAccessToken
            {
                UserId = dynamicObj[UserIdKey],
                AppId = dynamicObj[AppIdKey]
            };

            if (string.Equals(_googleAuthenticationOptions.ClientId, parsedToken.AppId, StringComparison.OrdinalIgnoreCase))
            {
                return parsedToken;
            }

            return null;
        }

        protected override string GetVerifyTokenEndPointUrl(string accessToken)
        {
            return string.Format(GoogleTokenValidationUrlFormat, accessToken);
        }

        protected override string GetProviderName()
        {
            return ProviderName;
        }

        private class GoogleOAuth2ParsedExternalAccessToken : ParsedExternalAccessToken
        {
            public string AppId { get; set; }
        }
    }
}