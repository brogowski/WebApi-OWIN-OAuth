using System;
using FullOAuth.ExternalAuthorization;
using FullOAuth.ExternalAuthorization.Extensions;
using Microsoft.Owin.Security.Facebook;
using Newtonsoft.Json.Linq;

namespace FullOAuth.Facebook
{
    class FacebookTokenValidator : AbstractExternalTokenValidator
    {
        private const string ProviderName = "Facebook";
        private const string FacebookValidationTokenUrlFormat = "https://graph.facebook.com/debug_token?input_token={0}&access_token={1}";
        private const string DataKey = "data";
        private const string UserIdKey = "user_id";
        private const string AppIdKey = "app_id";

        private readonly string _appToken;
        private readonly FacebookAuthenticationOptions _authenticationOptions;

        public FacebookTokenValidator(string appToken, FacebookAuthenticationOptions authenticationOptions)
        {
            _appToken = appToken;
            _authenticationOptions = authenticationOptions;            
        }

        protected override ParsedExternalAccessToken ParseExternalToken(JObject jObj)
        {
            dynamic dynamicObject = jObj;

            var parsedToken = new FacebookParsedExternalAccessToken
            {
                UserId = dynamicObject[DataKey][UserIdKey],
                AppId = dynamicObject[DataKey][AppIdKey]
            };

            if (string.Equals(_authenticationOptions.AppId, parsedToken.AppId, StringComparison.OrdinalIgnoreCase))
            {
                return parsedToken;
            }

            return null;
        }

        protected override string GetVerifyTokenEndPointUrl(string accessToken)
        {
            return string.Format(FacebookValidationTokenUrlFormat, accessToken, _appToken);
        }

        protected override string GetProviderName()
        {
            return ProviderName;
        }

        private class FacebookParsedExternalAccessToken : ParsedExternalAccessToken
        {
            public string AppId { get; set; }
        }
    }
}
