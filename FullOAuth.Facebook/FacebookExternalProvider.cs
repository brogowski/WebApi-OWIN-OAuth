using System;
using FullOAuth.ExternalAuthorization.Extensions;
using FullOAuth.OWIN;
using Microsoft.Owin.Security.Facebook;
using Owin;

namespace FullOAuth.Facebook
{
    public class FacebookExternalProvider : IExternalProvider
    {
        private FacebookAuthenticationOptions _authenticationOptions;
        private IExternalProviderTokenValidator _tokenValidator;
        private readonly string _appId;
        private readonly string _appSecret;
        private readonly string _appToken;

        public FacebookExternalProvider(string appId, string appSecret, string appToken)
        {
            _appId = appId;
            _appSecret = appSecret;
            _appToken = appToken;
        }

        public void Setup(IAppBuilder app)
        {
            _authenticationOptions = GetAuthenticationOptions();
            _tokenValidator = new FacebookTokenValidator(_appToken, _authenticationOptions);

            app.UseFacebookAuthentication(_authenticationOptions);
        }

        public IExternalProviderTokenValidator GetTokenValidator()
        {
            return _tokenValidator;
        }

        private FacebookAuthenticationOptions GetAuthenticationOptions()
        {
            return new FacebookAuthenticationOptions
            {
                Provider = new FacebookAuthProvider(),
                AppId = _appId,
                AppSecret = _appSecret
            };
        }
    }
}
