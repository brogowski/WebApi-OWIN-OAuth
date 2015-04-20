using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using FullOAuth.ExternalAuthorization;
using FullOAuth.ExternalAuthorization.Extensions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace FullOAuth.Microsoft
{
    public class MicrosoftTokenValidator : IExternalProviderTokenValidator
    {
        private const string ProviderName = "Microsoft";

        public bool CanValidate(string provider)
        {
            return provider == ProviderName;
        }

        public async Task<ParsedExternalAccessToken> ParseExternalTokenAsync(string accessToken)
        {
            var client = new HttpClient();
            var response = await client.GetAsync(string.Format("https://apis.live.net/v5.0/me?access_token={0}", accessToken));

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                return ParseExternalToken((JObject)JsonConvert.DeserializeObject(content));
            }

            return null;
        }

        private ParsedExternalAccessToken ParseExternalToken(JObject deserializeObject)
        {
            return new ParsedExternalAccessToken
            {
                UserId = deserializeObject["id"].ToString()
            };
        }
    }
}