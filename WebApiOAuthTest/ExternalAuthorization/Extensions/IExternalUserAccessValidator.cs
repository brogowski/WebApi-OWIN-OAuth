using FullOAuth.DAL.Models;

namespace FullOAuth.ExternalAuthorization.Extensions
{
    public interface IExternalUserAccessValidator
    {
        User ValidateLogin(ExternalUserLoginInfo userLoginInfo);
    }
}