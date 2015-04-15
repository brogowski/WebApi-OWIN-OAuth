using FullOAuth.ExternalAuthorization.Extensions;
using Owin;

namespace FullOAuth.OWIN
{
    public interface IExternalProvider
    {
        void Setup(IAppBuilder app);
        IExternalProviderTokenValidator GetTokenValidator();
    }
}