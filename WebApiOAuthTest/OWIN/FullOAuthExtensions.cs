using System.Collections.Generic;
using FullOAuth.AuthorizationServer.Extensions;
using FullOAuth.DAL;

namespace FullOAuth.OWIN
{
    public class FullOAuthExtensions
    {
        public IClientRepo ClientRepo { get; set; }
        public IHashingProvider Hasher { get; set; }
        public IUserAccessValidator AccessValidator { get; set; }
        public IRefreshTokenRepo RefreshTokenRepo { get; set; }
        public IEnumerable<IExternalProvider> ExternalProviders { get; set; }
    }
}