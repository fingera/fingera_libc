#include <fingera_libc/btc/exkey.h>
#include <fingera_libc/btc/key.h>
#include <fingera_libc/hex.h>
#include <fingera_libc/random.h>

#include <gtest/gtest.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>

struct TestDerivation {
  std::string pub;
  std::string prv;
  unsigned int nChild;
};

struct TestVector {
  std::string strHexMaster;
  std::vector<TestDerivation> vDerive;

  explicit TestVector(std::string strHexMasterIn)
      : strHexMaster(strHexMasterIn) {}

  TestVector& operator()(std::string pub, std::string prv,
                         unsigned int nChild) {
    vDerive.push_back(TestDerivation());
    TestDerivation& der = vDerive.back();
    der.pub = pub;
    der.prv = prv;
    der.nChild = nChild;
    return *this;
  }
};

TestVector test1 = TestVector("000102030405060708090a0b0c0d0e0f")(
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1R"
    "upje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWU"
    "tg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
    0x80000000)(
    "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsf"
    "TFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
    "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesn"
    "DYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
    1)(
    "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5"
    "uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
    "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgb"
    "oyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
    0x80000002)(
    "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGT"
    "sxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
    "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4"
    "ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
    2)(
    "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQU"
    "Mv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
    "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7Rty"
    "zTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
    1000000000)(
    "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxup"
    "HiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
    "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggL"
    "yQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
    0);

TestVector test2 = TestVector(
    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693"
    "908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")(
    "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6"
    "Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
    "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFm"
    "M8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
    0)(
    "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnK"
    "ZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
    "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9m"
    "krocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
    0xFFFFFFFF)(
    "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSA"
    "RLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
    "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vn"
    "xVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
    1)(
    "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGo"
    "WaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
    "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog6"
    "2tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
    0xFFFFFFFE)(
    "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5J"
    "aHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
    "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyu"
    "oseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
    2)(
    "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME"
    "5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
    "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGf"
    "Sh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
    0);

TestVector test3 = TestVector(
    "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d23931"
    "9ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")(
    "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6"
    "SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
    "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph"
    "3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
    0x80000000)(
    "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4"
    "CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
    "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqd"
    "q6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
    0);

bool compare(fingera_ex_extension& ex1, fingera_ex_extension& ex2) {
  return ex1.child == ex2.child && ex1.depth == ex2.depth &&
         ex1.fingerprint == ex2.fingerprint &&
         memcmp(ex1.chain_code, ex2.chain_code, sizeof(ex1.chain_code)) == 0;
}

bool compare(fingera_ex_key& key1, fingera_ex_key& key2) {
  return memcmp(key1.key, key2.key, sizeof(key1.key)) == 0 &&
         compare(key1.ext, key2.ext);
}

bool compare(fingera_ex_pubkey& key1, fingera_ex_pubkey& key2) {
  return memcmp(key1.c_pubkey, key2.c_pubkey, sizeof(key1.c_pubkey)) == 0 &&
         compare(key1.ext, key2.ext);
}

static void RunTest(const TestVector& test) {
  std::vector<unsigned char> seed;
  seed.resize(fingera_from_hex_length(test.strHexMaster.size()));
  fingera_from_hex(test.strHexMaster.c_str(), test.strHexMaster.size(),
                   &seed[0]);
  fingera_ex_key key = {0};
  fingera_ex_pubkey pubkey = {0};
  fingera_exkey_init(&key, seed.data(), seed.size());
  fingera_exkey_get_pub(&key, &pubkey);
  for (const TestDerivation& derive : test.vDerive) {
    char str_key[256];
    fingera_ex_key dec_key = {0};
    fingera_ex_pubkey dec_pub_key = {0};
    EXPECT_TRUE(fingera_exkey_string_max_length() < 256);

    size_t str_key_size =
        fingera_exkey_to_string(&key, str_key, &g_mainnet_chain_parameters);
    str_key[str_key_size] = '\0';
    EXPECT_EQ(derive.prv, str_key);

    EXPECT_TRUE(fingera_exkey_from_string(str_key, str_key_size, &dec_key,
                                          &g_mainnet_chain_parameters));
    EXPECT_TRUE(compare(key, dec_key));

    str_key_size = fingera_expubkey_to_string(&pubkey, str_key,
                                              &g_mainnet_chain_parameters);
    str_key[str_key_size] = '\0';
    EXPECT_EQ(derive.pub, str_key);
    EXPECT_TRUE(fingera_expubkey_from_string(
        str_key, str_key_size, &dec_pub_key, &g_mainnet_chain_parameters));
    EXPECT_TRUE(compare(pubkey, dec_pub_key));

    // Derive new keys
    fingera_ex_key keyNew = {0};
    EXPECT_TRUE(fingera_exkey_derive(&key, &keyNew, derive.nChild,
                                     fingera_btc_key_fingerprint(key.key, 1)));

    fingera_ex_pubkey pubkeyNew = {0};
    fingera_exkey_get_pub(&keyNew, &pubkeyNew);
    if (!(derive.nChild & 0x80000000)) {
      // Compare with public derivation
      fingera_ex_pubkey pubkeyNew2;
      EXPECT_TRUE(fingera_expubkey_derive(
          &pubkey, &pubkeyNew2, derive.nChild,
          fingera_btc_pubkey_fingerprint(pubkey.c_pubkey)));

      EXPECT_EQ(pubkeyNew.ext.child, pubkeyNew2.ext.child);
      EXPECT_EQ(pubkeyNew.ext.depth, pubkeyNew2.ext.depth);
      EXPECT_EQ(pubkeyNew.ext.fingerprint, pubkeyNew2.ext.fingerprint);
      EXPECT_FALSE(memcmp(pubkeyNew.c_pubkey, pubkeyNew2.c_pubkey, 33));
      EXPECT_FALSE(
          memcmp(pubkeyNew.ext.chain_code, pubkeyNew2.ext.chain_code, 32));
    }
    memcpy(&key, &keyNew, sizeof(keyNew));
    memcpy(&pubkey, &pubkeyNew, sizeof(pubkeyNew));
  }
}

TEST(exkey, bip32_test1) {
  fingera_btc_key_init();
  RunTest(test1);
  fingera_btc_key_uninit();
}

TEST(exkey, bip32_test2) {
  fingera_btc_key_init();
  RunTest(test2);
  fingera_btc_key_uninit();
}

TEST(exkey, bip32_test3) {
  fingera_btc_key_init();
  RunTest(test3);
  fingera_btc_key_uninit();
}