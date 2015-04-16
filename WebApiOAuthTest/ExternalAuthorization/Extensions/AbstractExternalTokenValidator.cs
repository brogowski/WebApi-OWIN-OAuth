using System;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace FullOAuth.ExternalAuthorization.Extensions
{
    public abstract class AbstractExternalTokenValidator : IExternalProviderTokenValidator
    {
        public bool CanValidate(string provider)
        {
            return provider == GetProviderName();
        }

        public async Task<ParsedExternalAccessToken> ParseExternalTokenAsync(string accessToken)
        {
            var verifyTokenEndPoint = string.Format(GetVerifyTokenEndPointUrl(accessToken));

            var client = new HttpClient();
            var uri = new Uri(verifyTokenEndPoint);
            var response = await client.GetAsync(uri);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                return ParseExternalToken((JObject)JsonConvert.DeserializeObject(content));
            }

            return null;
        }

        protected abstract ParsedExternalAccessToken ParseExternalToken(JObject jObj);

        protected abstract string GetVerifyTokenEndPointUrl(string accessToken);

        protected abstract string GetProviderName();
    }
}
