using System;
using System.Threading.Tasks;
using FullOAuth.AuthorizationServer.Extensions;
using FullOAuth.DAL;
using FullOAuth.DAL.Models;
using FullOAuth.Properties;
using Microsoft.Owin.Security.Infrastructure;

namespace FullOAuth.AuthorizationServer
{
    public class SimpleRefreshTokenProvider : AuthenticationTokenProvider
    {
        private readonly IHashingProvider _hasher;
        private readonly IRefreshTokenRepo _refreshTokenRepo;

        public SimpleRefreshTokenProvider(IHashingProvider hasher, IRefreshTokenRepo refreshTokenRepo)
        {
            _hasher = hasher;
            _refreshTokenRepo = refreshTokenRepo;
        }

        public override async Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            var clientid = context.Ticket.Properties.Dictionary[Constants.ClientIdKey];

            if (string.IsNullOrEmpty(clientid))
            {
                return;
            }

            var refreshTokenId = Guid.NewGuid().ToString("n");


            var refreshTokenLifeTime = context.OwinContext.Get<string>(Constants.ClientRefreshTokenLifetimeKey);

            var token = new RefreshToken
            {
                Id = _hasher.Hash(refreshTokenId),
                ClientId = clientid,
                Subject = context.Ticket.Identity.Name,
                IssuedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(Convert.ToDouble(refreshTokenLifeTime))
            };

            context.Ticket.Properties.IssuedUtc = token.IssuedUtc;
            context.Ticket.Properties.ExpiresUtc = token.ExpiresUtc;

            token.ProtectedTicket = context.SerializeTicket();

            var result = _refreshTokenRepo.AddRefreshToken(token);

            if (result)
            {
                context.SetToken(refreshTokenId);
            }
        }

        public override async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            var allowedOrigin = context.OwinContext.Get<string>(Constants.ClientAllowedOriginKey);
            context.OwinContext.Response.Headers.Add(Constants.AllowedOriginHeader, new[] { allowedOrigin });

            var hashedTokenId = _hasher.Hash(context.Token);

            var refreshToken = _refreshTokenRepo.FindRefreshToken(hashedTokenId);

            if (refreshToken != null)
            {
                context.DeserializeTicket(refreshToken.ProtectedTicket);
                _refreshTokenRepo.RemoveRefreshToken(hashedTokenId);
            }
        }
    }
}