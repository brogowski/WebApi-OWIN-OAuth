using System;
using System.Collections.Generic;
using System.Security.Claims;
using FullOAuth.ExternalAuthorization.Extensions;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;

namespace FullOAuth.ExternalAuthorization.Bearer
{
    class OAuthBearerAccessTokenGenerator : IAccessTokenGenerator
    {
        private readonly OAuthBearerAuthenticationOptions _bearerAuthenticationOptions;
        private readonly IClaimsProvider _claimsProvider;

        public OAuthBearerAccessTokenGenerator(OAuthBearerAuthenticationOptions authenticationOptions, IClaimsProvider claimsProvider)
        {
            _bearerAuthenticationOptions = authenticationOptions;
            _claimsProvider = claimsProvider;
        }

        public IReadOnlyDictionary<string, string> GenerateAccessToken(string userName)
        {
            var tokenExpiration = TimeSpan.FromDays(1);

            ClaimsIdentity identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);

            _claimsProvider.SetClaimsForUser(userName, identity);

            var props = new AuthenticationProperties
            {
                IssuedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.Add(tokenExpiration),
            };

            var ticket = new AuthenticationTicket(identity, props);

            var accessToken = _bearerAuthenticationOptions.AccessTokenFormat.Protect(ticket);

            return new Dictionary<string, string>
            {
                {"userName", userName},
                {"access_token", accessToken},
                {"token_type", "bearer"},
                {"expires_in", tokenExpiration.TotalSeconds.ToString()},
                {".issued", ticket.Properties.IssuedUtc.ToString()},
                {".expires", ticket.Properties.ExpiresUtc.ToString()}
            };
        }
    }
}