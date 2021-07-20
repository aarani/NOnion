using NOnion.Crypto.Kdf;

namespace DotNetOnion.KeyAgreements
{
    public interface IKeyAgreement
    {
        byte[] CreateClientMaterial();
        KdfResult CalculateKey(byte[] serverResponse);
    }
}