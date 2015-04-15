using System.Threading.Tasks;

namespace FullOAuth.ExternalAuthorization.Extensions
{
    public interface IExternalProviderTokenValidator
    {
        bool CanValidate(string provider);
        Task<ParsedExternalAccessToken> ParseExternalTokenAsync(string accessToken);
    }
}