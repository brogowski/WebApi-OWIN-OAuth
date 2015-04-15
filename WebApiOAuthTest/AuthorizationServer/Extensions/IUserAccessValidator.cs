namespace FullOAuth.AuthorizationServer.Extensions
{
    public interface IUserAccessValidator
    {
        bool Validate(string userName, string password);
    }
}