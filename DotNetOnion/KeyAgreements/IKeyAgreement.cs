using DotNetOnion.Crypto.KDF;

namespace DotNetOnion.KeyAgreements
{
    public interface IKeyAgreement
    {
        byte[] CreateClientMaterial();
        TorKdfResult CalculateKey(byte[] serverResponse);
    }
}