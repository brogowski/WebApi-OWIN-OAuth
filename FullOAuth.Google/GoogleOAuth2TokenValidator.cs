using System;
using System.Net.Http;
using System.Threading.Tasks;
using FullOAuth.ExternalAuthorization;
using FullOAuth.ExternalAuthorization.Extensions;
using Microsoft.Owin.Security.Google;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace FullOAuth.Google
{
    class GoogleOAuth2TokenValidator : IExternalProviderTokenValidator
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

        public bool CanValidate(string provider)
        {
            return ProviderName == provider;
        }

        public async Task<ParsedExternalAccessToken> ParseExternalTokenAsync(string accessToken)
        {
            var verifyTokenEndPoint = string.Format(GoogleTokenValidationUrlFormat, accessToken);

            var client = new HttpClient();
            var uri = new Uri(verifyTokenEndPoint);
            var response = await client.GetAsync(uri);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                dynamic jObj = (JObject) JsonConvert.DeserializeObject(content);

                var parsedToken = new GoogleOAuth2ParsedExternalAccessToken
                {
                    UserId = jObj[UserIdKey],
                    AppId = jObj[AppIdKey]
                };

                if (string.Equals(_googleAuthenticationOptions.ClientId, parsedToken.AppId, StringComparison.OrdinalIgnoreCase))
                {
                    return parsedToken;
                }
            }

            return null;
        }

        private class GoogleOAuth2ParsedExternalAccessToken : ParsedExternalAccessToken
        {
            public string AppId { get; set; }
        }
    }
}