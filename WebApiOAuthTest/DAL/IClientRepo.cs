using FullOAuth.DAL.Models;

namespace FullOAuth.DAL
{
    public interface IClientRepo
    {
        Client FindClient(string clientId);
    }
}