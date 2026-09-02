using Chizl.Crypto;

namespace NUnitTests
{
    [Parallelizable(ParallelScope.Self)]
    [TestFixture]
    public class AesHmacStringTests
    {
        [TestCase("This is a test string to be encrypted.", "P@$$w0rd", "P@$$w0rd", true, true)]            // positive testing, valid password
        [TestCase("This is a test string to be encrypted.", "P@$$w0rd", "Passw0rd", true, false)]           // negative testing, invalid decrypt password
        [Category("HMAC")]
        public async Task EncAndDecBoolReturn(string testString, string encPass, string decPass, bool encExpectedResult, bool decExpectedResult)
        {
            var hmac = new AesHmacVault();

            var encSuccess = hmac.Encrypt(testString, encPass.AsSpan(), out string? encryptedData);
            Assert.That(encSuccess, Is.EqualTo(encExpectedResult));

            if (encSuccess)
                Assert.That(hmac.LastError, Is.Null.Or.Empty, "LastError should be empty on successful encryption.");
            else
            {
                Assert.That(hmac.LastError, Is.Not.Null.And.Not.Empty, "LastError should contain an error message on failed encryption.");
                return;
            }

            if (!string.IsNullOrWhiteSpace(encryptedData))
            {
                var decSuccess = hmac.Decrypt(encryptedData, decPass.AsSpan(), out string? decryptedData);
                Assert.That(decSuccess, Is.EqualTo(decExpectedResult));

                var result = testString.Equals(decryptedData);
                Assert.That(result, Is.EqualTo(decExpectedResult));

                // since negative testing will have failure on decrypt, evaluation is different that encrypt.
                Assert.That(hmac.LastError, decSuccess ? Is.Null.Or.Empty : Is.Not.Null.Or.Empty);
            }
        }

        [TestCase("This is a test string to be encrypted.", "P@$$w0rd", "P@$$w0rd", true, true)]            // positive testing, valid password
        [TestCase("This is a test string to be encrypted.", "P@$$w0rd", "Passw0rd", true, false)]           // negative testing, invalid decrypt password
        [Category("HMAC")]
        public async Task EncAndDecStringReturn(string testString, string encPass, string decPass, bool encExpectedResult, bool decExpectedResult)
        {
            var hmac = new AesHmacVault();

            string? encryptedData = hmac.Encrypt(testString, encPass);
            var encSuccess = !string.IsNullOrWhiteSpace(encryptedData);

            Assert.That(encSuccess, Is.EqualTo(encExpectedResult));

            if (encSuccess)
                Assert.That(hmac.LastError, Is.Null.Or.Empty, "LastError should be empty on successful encryption.");
            else
            {
                Assert.That(hmac.LastError, Is.Not.Null.And.Not.Empty, "LastError should contain an error message on failed encryption.");
                return;
            }

            if (!string.IsNullOrWhiteSpace(encryptedData))
            {
                var decryptedData = hmac.Decrypt(encryptedData, decPass);
                var decSuccess = !string.IsNullOrWhiteSpace(decryptedData);
                
                Assert.That(decSuccess, Is.EqualTo(decExpectedResult));

                var result = testString.Equals(decryptedData);
                Assert.That(result, Is.EqualTo(decExpectedResult));

                // since negative testing will have failure on decrypt, evaluation is different that encrypt.
                Assert.That(hmac.LastError, decSuccess ? Is.Null.Or.Empty : Is.Not.Null.Or.Empty);
            }
        }
    }
}
