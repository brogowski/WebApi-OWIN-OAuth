namespace FullOAuth.ExternalAuthorization.Extensions
{
    public interface IExternalUserProvider
    {
        void RegisterUser(string userName);
        void AddLogin(string userName, ExternalUserLoginInfo login);
    }
}