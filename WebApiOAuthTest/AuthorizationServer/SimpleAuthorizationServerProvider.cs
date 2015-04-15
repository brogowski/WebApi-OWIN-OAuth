using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using FullOAuth.AuthorizationServer.Extensions;
using FullOAuth.DAL;
using FullOAuth.DAL.Models;
using FullOAuth.Properties;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;

namespace FullOAuth.AuthorizationServer
{
    internal class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        private readonly IClientRepo _clientRepo;
        private readonly IHashingProvider _hasher;
        private readonly IUserAccessValidator _userAccessValidator;

        public SimpleAuthorizationServerProvider(IClientRepo clientRepo, IHashingProvider hasher,
            IUserAccessValidator userAccessValidator)
        {
            _clientRepo = clientRepo;
            _hasher = hasher;
            _userAccessValidator = userAccessValidator;
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId;
            string clientSecret;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);                
            }

            if (context.ClientId == null)
            {
                context.SetError(Constants.InvalidClientId, "ClientId should be sent.");
                return Task.FromResult<object>(null);
            }

            var client = _clientRepo.FindClient(context.ClientId);


            if (client == null)
            {
                context.SetError(Constants.InvalidClientId,
                    string.Format("Client '{0}' is not registered in the system.", context.ClientId));
                return Task.FromResult<object>(null);
            }

            if (client.ApplicationType == ApplicationTypes.NativeConfidential)
            {
                if (string.IsNullOrWhiteSpace(clientSecret))
                {
                    context.SetError(Constants.InvalidClientId, "Client secret should be sent.");
                    return Task.FromResult<object>(null);
                }
                else
                {
                    if (client.Secret != _hasher.Hash(clientSecret))
                    {
                        context.SetError(Constants.InvalidClientId, "Client secret is invalid.");
                        return Task.FromResult<object>(null);
                    }
                }
            }

            if (!client.Active)
            {
                context.SetError(Constants.InvalidClientId, "Client is inactive.");
                return Task.FromResult<object>(null);
            }

            context.OwinContext.Set(Constants.ClientAllowedOriginKey, client.AllowedOrigin);
            context.OwinContext.Set(Constants.ClientRefreshTokenLifetimeKey, client.RefreshTokenLifeTime.ToString());

            context.Validated();
            return Task.FromResult<object>(null);
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var allowedOrigin = context.OwinContext.Get<string>(Constants.ClientAllowedOriginKey) ?? Constants.AllowAllOrigins;

            context.OwinContext.Response.Headers.Add(Constants.AllowedOriginHeader, new[] {allowedOrigin});

            if (!_userAccessValidator.Validate(context.UserName, context.Password))
            {
                context.SetError(Constants.InvalidGrant, "The user name or password is incorrect.");
                return;
            }

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            identity.AddClaim(new Claim(ClaimTypes.Role, "user"));

            var props = new AuthenticationProperties(new Dictionary<string, string>
            {
                {
                    Constants.ClientIdKey, context.ClientId ?? string.Empty
                },
                {
                    "userName", context.UserName
                }
            });

            var ticket = new AuthenticationTicket(identity, props);
            context.Validated(ticket);

        }

        public override async Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (var property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }
        }

        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary[Constants.ClientIdKey];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.SetError(Constants.InvalidClientId, "Refresh token is issued to a different clientId.");
                return Task.FromResult<object>(null);
            }

            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);
            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            context.Validated(newTicket);

            return Task.FromResult<object>(null);
        }
    }
}