using DotNetOnion.Crypto.KDF;

namespace DotNetOnion.KeyAgreements
{
    internal interface IKeyAgreement
    {
        byte[] CreateClientMaterial();
        TorKdfResult CalculateKey(byte[] serverResponse);
    }
}