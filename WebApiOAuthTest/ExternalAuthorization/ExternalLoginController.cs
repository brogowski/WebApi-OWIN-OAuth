using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using FullOAuth.DAL;
using FullOAuth.ExternalAuthorization.Extensions;
using FullOAuth.OWIN;
using Microsoft.AspNet.Identity;
using Newtonsoft.Json.Linq;
using Constants = FullOAuth.Properties.Constants;

namespace FullOAuth.ExternalAuthorization
{
    public abstract class ExternalLoginController : ApiController
    {
        private readonly IEnumerable<IExternalProviderTokenValidator> _providerTokenValidators;
        private readonly IExternalUserAccessValidator _userAccessValidator;
        private readonly IExternalUserProvider _externalUserProvider;
        private readonly IAccessTokenGenerator _accessTokenGenerator;
        private readonly IClientRepo _clientRepo;

        protected ExternalLoginController(IExternalUserAccessValidator userAccessValidator,
            IExternalUserProvider externalUserProvider, IClientRepo clientRepo,
            IClaimsProvider claimsProvider)
        {
            _providerTokenValidators = OwinExtensions.ExternalProviders.Select(q => q.GetTokenValidator());
            _accessTokenGenerator = OwinExtensions.GetAccessTokenGenerator(claimsProvider);
            _userAccessValidator = userAccessValidator;
            _externalUserProvider = externalUserProvider;
            _clientRepo = clientRepo;
        }

        protected async Task<IHttpActionResult> ExternalLoginAsync(string provider, string error = null)
        {
            string redirectUri = string.Empty;

            if (error != null)
            {
                return BadRequest(Uri.EscapeDataString(error));
            }

            if (User == null || !User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(provider, Request);
            }

            var redirectUriValidationResult = ValidateClientAndRedirectUri(Request, ref redirectUri);

            if (!string.IsNullOrWhiteSpace(redirectUriValidationResult))
            {
                return BadRequest(redirectUriValidationResult);
            }

            var externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != provider)
            {
                Request.GetOwinContext().Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, Request);
            }

            var hasRegistered = _userAccessValidator.ValidateLogin(new ExternalUserLoginInfo(externalLogin.LoginProvider, externalLogin.ProviderKey));

            redirectUri = string.Format("{0}#external_access_token={1}&provider={2}&haslocalaccount={3}&external_user_name={4}",
                                            redirectUri,
                                            externalLogin.ExternalAccessToken,
                                            externalLogin.LoginProvider,
                                            hasRegistered,
                                            externalLogin.UserName);

            return Redirect(redirectUri);
        }

        protected async Task<IHttpActionResult> ExternalRegisterAsync(RegisterExternalBindingModel model)
        {
            var verifiedAccessToken = await VerifyExternalAccessTokenAsync(model.Provider, model.ExternalAccessToken);

            if (verifiedAccessToken == null)
            {
                return BadRequest("Invalid Provider or External Access Token");
            }

            var user = _userAccessValidator.ValidateLogin(new ExternalUserLoginInfo(model.Provider, verifiedAccessToken.UserId));

            if (user != null)
            {
                return BadRequest("External user is already registered");
            }

            _externalUserProvider.RegisterUser(model.UserName);

            _externalUserProvider.AddLogin(model.UserName, new ExternalUserLoginInfo(model.Provider, verifiedAccessToken.UserId));

            var accessTokenResponse = _accessTokenGenerator.GenerateAccessToken(model.UserName);

            return Ok(accessTokenResponse);
        }

        protected async Task<IHttpActionResult> ObtainLocalAccessTokenAsync(string provider, string externalAccessToken)
        {
            if (string.IsNullOrWhiteSpace(provider) || string.IsNullOrWhiteSpace(externalAccessToken))
            {
                return BadRequest("Provider or external access token is not sent");
            }

            var verifiedAccessToken = await VerifyExternalAccessTokenAsync(provider, externalAccessToken);

            if (verifiedAccessToken == null)
            {
                return BadRequest("Invalid Provider or External Access Token");
            }

            var user = _userAccessValidator.ValidateLogin(new ExternalUserLoginInfo(provider, verifiedAccessToken.UserId));

            if (user == null)
            {
                return BadRequest("External user is not registered");
            }

            var accessTokenResponse = _accessTokenGenerator.GenerateAccessToken(user.UserName);

            return Ok(JObject.FromObject(accessTokenResponse));
        }

        private string ValidateClientAndRedirectUri(HttpRequestMessage request, ref string redirectUriOutput)
        {
            Uri redirectUri;

            var redirectUriString = GetQueryString(request, "redirect_uri");

            if (string.IsNullOrWhiteSpace(redirectUriString))
            {
                return "redirect_uri is required";
            }

            bool validUri = Uri.TryCreate(redirectUriString, UriKind.Absolute, out redirectUri);

            if (!validUri)
            {
                return "redirect_uri is invalid";
            }

            var clientId = GetQueryString(Request, "client_id");

            if (string.IsNullOrWhiteSpace(clientId))
            {
                return "client_Id is required";
            }

            var client = _clientRepo.FindClient(clientId);

            if (client == null)
            {
                return string.Format("Client_id '{0}' is not registered in the system.", clientId);
            }

            if (client.AllowedOrigin != "*" && !string.Equals(client.AllowedOrigin, redirectUri.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase))
            {
                return string.Format("The given URL is not allowed by Client_id '{0}' configuration.", clientId);
            }

            redirectUriOutput = redirectUri.AbsoluteUri;

            return string.Empty;

        }

        private string GetQueryString(HttpRequestMessage request, string key)
        {
            var queryStrings = request.GetQueryNameValuePairs();

            if (queryStrings == null) return null;

            var match = queryStrings.FirstOrDefault(keyValue => String.Compare(keyValue.Key, key, StringComparison.OrdinalIgnoreCase) == 0);

            if (string.IsNullOrEmpty(match.Value)) return null;

            return match.Value;
        }

        private async Task<ParsedExternalAccessToken> VerifyExternalAccessTokenAsync(string provider, string accessToken)
        {
            if (_providerTokenValidators.All(q => !q.CanValidate(provider)))
            {
                return null;
            }

            return await _providerTokenValidators.First(q => q.CanValidate(provider)).ParseExternalTokenAsync(accessToken);
        }

        private class ExternalLoginData
        {
            public string LoginProvider { get; private set; }
            public string ProviderKey { get; private set; }
            public string UserName { get; private set; }
            public string ExternalAccessToken { get; private set; }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer) || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name),
                    ExternalAccessToken = identity.FindFirstValue(Constants.ExternalAccessTokenKey),
                };
            }
        }
    }
}
