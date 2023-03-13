// Copyright 2022 Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Security.Cryptography;
using Xunit;
using Yubico.Core.Cryptography;

namespace UnitTests
{
    public class ComputeSharedSecretTests
    {
        [Fact]
        public void ComputeSecret_Matches()
        {
            IEcdhPrimitives ecdhObject = EcdhPrimitives.Create();

            ECCurve ecCurve = ECCurve.NamedCurves.nistP256;

            ECParameters keyPairA = ecdhObject.GenerateKeyPair(ecCurve);
            ECParameters keyPairB = ecdhObject.GenerateKeyPair(ecCurve);

            byte[] secretA = ecdhObject.ComputeSharedSecret(keyPairB, keyPairA.D);
            byte[] secretB = ecdhObject.ComputeSharedSecret(keyPairA, keyPairB.D);

            bool isValid = MemoryExtensions.SequenceEqual(secretA.AsSpan(), secretB.AsSpan());

            Assert.True(isValid);
        }
    }
}
