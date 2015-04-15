using FullOAuth.DAL.Models;

namespace FullOAuth.DAL
{
    public interface IRefreshTokenRepo
    {
        bool AddRefreshToken(RefreshToken token);
        RefreshToken FindRefreshToken(string hashedTokenId);
        void RemoveRefreshToken(string hashedTokenId);
    }
}