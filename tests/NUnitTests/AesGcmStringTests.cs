using Chizl.Crypto;

namespace NUnitTests
{
    [Parallelizable(ParallelScope.Self)]
    [TestFixture]
    public class AesGcmStringTests
    {
        [TestCase("This is a test string to be encrypted.", "P@$$w0rd", "P@$$w0rd", true, true)]            // positive testing, valid password
        [TestCase("This is a test string to be encrypted.", "P@$$w0rd", "Passw0rd", true, false)]           // negative testing, invalid decrypt password
        [Category("GCM")]
        public async Task EncAndDecBoolReturn(string testString, string encPass, string decPass, bool encExpectedResult, bool decExpectedResult)
        {
            var gcm = new AesGcmVault();

            var encSuccess = gcm.Encrypt(testString, encPass.AsSpan(), out string? encryptedData);
            Assert.That(encSuccess, Is.EqualTo(encExpectedResult));

            if (encSuccess)
                Assert.That(gcm.LastError, Is.Null.Or.Empty, "LastError should be empty on successful encryption.");
            else
            {
                Assert.That(gcm.LastError, Is.Not.Null.And.Not.Empty, "LastError should contain an error message on failed encryption.");
                return;
            }

            if (!string.IsNullOrWhiteSpace(encryptedData))
            {
                var decSuccess = gcm.Decrypt(encryptedData, decPass.AsSpan(), out string? decryptedData);
                Assert.That(decSuccess, Is.EqualTo(decExpectedResult));

                var result = testString.Equals(decryptedData);
                Assert.That(result, Is.EqualTo(decExpectedResult));

                // since negative testing will have failure on decrypt, evaluation is different that encrypt.
                Assert.That(gcm.LastError, decSuccess ? Is.Null.Or.Empty : Is.Not.Null.Or.Empty);
            }
        }

        [TestCase("This is a test string to be encrypted.", "P@$$w0rd", "P@$$w0rd", true, true)]            // positive testing, valid password
        [TestCase("This is a test string to be encrypted.", "P@$$w0rd", "Passw0rd", true, false)]           // negative testing, invalid decrypt password
        [Category("GCM")]
        public async Task EncAndDecStringReturn(string testString, string encPass, string decPass, bool encExpectedResult, bool decExpectedResult)
        {
            var gcm = new AesGcmVault();

            string? encryptedData = gcm.Encrypt(testString, encPass);
            var encSuccess = !string.IsNullOrWhiteSpace(encryptedData);

            Assert.That(encSuccess, Is.EqualTo(encExpectedResult));

            if (encSuccess)
                Assert.That(gcm.LastError, Is.Null.Or.Empty, "LastError should be empty on successful encryption.");
            else
            {
                Assert.That(gcm.LastError, Is.Not.Null.And.Not.Empty, "LastError should contain an error message on failed encryption.");
                return;
            }

            if (!string.IsNullOrWhiteSpace(encryptedData))
            {
                var decryptedData = gcm.Decrypt(encryptedData, decPass);
                var decSuccess = !string.IsNullOrWhiteSpace(decryptedData);
                Assert.That(decSuccess, Is.EqualTo(decExpectedResult));

                var result = testString.Equals(decryptedData);
                Assert.That(result, Is.EqualTo(decExpectedResult));

                // since negative testing will have failure on decrypt, evaluation is different that encrypt.
                Assert.That(gcm.LastError, decSuccess ? Is.Null.Or.Empty : Is.Not.Null.Or.Empty);
            }
        }
    }
}
