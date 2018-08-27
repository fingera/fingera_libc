#include <fingera_libc/btc/address.h>
#include <fingera_libc/btc/base58_check.h>
#include <fingera_libc/hex.h>

#include <gtest/gtest.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>

#define EXPECT_ZERO(x) EXPECT_EQ((x), 0)

static void test_address(const std::string &encoded, const std::string &hex,
                         const chain_parameters *param) {
  EXPECT_TRUE(hex.size() % 2 == 0);
  std::vector<uint8_t> data;
  data.resize(hex.size() / 2);
  EXPECT_EQ(fingera_from_hex(hex.c_str(), hex.size(), data.data()),
            data.size());

  char decoded_address[512];
  size_t decoded_address_size = sizeof(decoded_address);
  fingera_btc_address addr =
      fingera_btc_address_decode(encoded.c_str(), encoded.size(),
                                 decoded_address, &decoded_address_size, param);

  EXPECT_TRUE(decoded_address_size > 0);
  EXPECT_TRUE(addr != BTC_BAD_ADDRESS);
  char new_address[256];
  size_t new_address_size;
  switch (addr) {
    case BTC_PUBKEY_ADDRESS:
      // 76a914 OP_DUP OP_HASH160 OP_PUSH14(hex)
      EXPECT_ZERO(memcmp(data.data(), "\x76\xa9\x14", 3));
      EXPECT_EQ(decoded_address_size, 20);
      EXPECT_ZERO(memcmp(data.data() + 3, decoded_address, 20));
      new_address_size = fingera_to_address_pubkey(
          decoded_address, 20, new_address, sizeof(new_address), param);
      new_address[new_address_size] = '\0';
      EXPECT_EQ(new_address_size, encoded.size());
      EXPECT_EQ(encoded, new_address);
      break;
    case BTC_SCRIPT_ADDRESS:
      // a914 OP_HASH160 OP_PUSH14(hex)
      EXPECT_ZERO(memcmp(data.data(), "\xa9\x14", 2));
      EXPECT_EQ(decoded_address_size, 20);
      EXPECT_ZERO(memcmp(data.data() + 2, decoded_address, 20));
      new_address_size = fingera_to_address_script(
          decoded_address, 20, new_address, sizeof(new_address), param);
      new_address[new_address_size] = '\0';
      EXPECT_EQ(new_address_size, encoded.size());
      EXPECT_EQ(encoded, new_address);
      break;
    case BTC_WITNESSV0_KEYHASH_ADDRESS:
      EXPECT_ZERO(memcmp(data.data(), "\x00\x14", 2));
      EXPECT_EQ(decoded_address_size, 20);
      EXPECT_ZERO(memcmp(data.data() + 2, decoded_address, 20));
      new_address_size = fingera_to_address_witnessv0_keyhash(
          decoded_address, 20, new_address, sizeof(new_address), param);
      new_address[new_address_size] = '\0';
      EXPECT_EQ(new_address_size, encoded.size());
      EXPECT_EQ(encoded, new_address);
      // TODO: 增加大小写切换后测试
      break;
    case BTC_WITNESSV0_SCRIPTHASH_ADDRESS:
      EXPECT_ZERO(memcmp(data.data(), "\x00\x20", 2));
      EXPECT_EQ(decoded_address_size, 32);
      EXPECT_ZERO(memcmp(data.data() + 2, decoded_address, 32));
      new_address_size = fingera_to_address_witnessv0_scripthash(
          decoded_address, 32, new_address, sizeof(new_address), param);
      new_address[new_address_size] = '\0';
      EXPECT_EQ(new_address_size, encoded.size());
      EXPECT_EQ(encoded, new_address);
      // TODO: 增加大小写切换后测试
      break;
    case BTC_WITNESS_UNKNOWN_ADDRESS:
      EXPECT_TRUE(0x51 <= data[0] && data[1] <= 0x60);  // OP_1=>OP_16
      EXPECT_EQ(decoded_address_size - 1, data[1]);     // OP_PUSHx
      EXPECT_EQ(decoded_address_size + 1, data.size());
      EXPECT_ZERO(memcmp(data.data() + 2, decoded_address + 1,
                         decoded_address_size - 1));
      new_address_size = fingera_to_address_witness_unknown(
          decoded_address, decoded_address_size, new_address,
          sizeof(new_address), param);
      new_address[new_address_size] = '\0';
      EXPECT_EQ(new_address_size, encoded.size());
      EXPECT_EQ(encoded, new_address);
      // TODO: 增加大小写切换后测试
      break;
    default:
      EXPECT_FALSE(true);
      break;
  }
}

TEST(address, invalid) {
  char out[256];
  size_t out_size = 1;
  EXPECT_ZERO(fingera_to_address_pubkey("keyid", 5, out, 1,
                                        &g_mainnet_chain_parameters));
  EXPECT_ZERO(fingera_to_address_script("keyid", 5, out, 1,
                                        &g_mainnet_chain_parameters));
  EXPECT_EQ(fingera_btc_address_decode("keyid", 5, out, &out_size,
                                       &g_mainnet_chain_parameters),
            BTC_BAD_ADDRESS);
}

TEST(address, custom) {
  uint8_t buffer[512];
  char str[1024];
  const std::string out_str =
      "GFSDkyzbczs9RcQhey9QeYCkdiuDBpm9zwZ9E41pDnXLKrrkqJZqcTUewvCchKPUdARd6Ks2"
      "T7VLrPhRE8JfVKE1CkMk5YpfFRQv6QPE1RUWKSrgtj5Nv9xQUW7A4ZHzpaJeqrAzHEHAMaXd"
      "1YcKjV67bPvmmWEgbYWmoy9QpU6S4zbLq5Say71bvaUP7SZtttRHBnvA9hzzCT453KbGZpQ2"
      "VsbQFmGamwTs3Wi1eZTcnmuWGKPQik3UcQbqPkHpe5XwVyQYN1Te4EXRQ57Y2qtuSQKS8V9b"
      "2brSF9p8uKBgt7XuymMiMhGpaMU2kasoqFuprCXcRoLBGYdfsPaWUeDBBUq5PXeJmrdvERRq"
      "mYNpt3gFkf4PgrDLT15kdmJEmELpXwKkK2MBbm3ZbBZpVkiv5CzKT6U1cVen2n3tFAQnfW7N"
      "JHVhiYvEXKwr315XqWUHtBsoeNyfZULFXcLahx22ThWdiR2DGCB17Uox9CxcxidhnwXn3HUE"
      "2svGbaU4tSvuHtEpPd86NQaGu4CRJh5JQwabNLpe2QXi5p3nANNK7YCBNVo7AozRriJ8E4YF"
      "uhdu2wXaG9bzL7YC2aWciNWhoCxrPNFrRrm9bz5qew58T8RUCykoeuhBfyLWcUinknM6mjGe"
      "uei7tGcZatTWDHGLKrohMPGuKW1kEFcBnhgD1BX7PFsgz6HNJs3Bv6QsqeiVVUMxC";
  memset(buffer, 8, sizeof(buffer));
  memset(str, 0, sizeof(str));

  fingera_hex_dump(str, sizeof(str), 1);
  size_t str_len =
      fingera_to_base58_check(buffer, sizeof(buffer), "prefix", 6, str);
  EXPECT_LE(str_len, sizeof(str));
  EXPECT_EQ(str_len, out_str.size());
  str[str_len] = '\0';
  EXPECT_EQ(out_str, str);

  str_len = sizeof(str);
  EXPECT_ZERO(fingera_btc_address_decode(
      "xx1qpqyqszqgpqyqszqgpqyqszqgpqyqszqg23t9q4", 42, str, &str_len,
      &g_mainnet_chain_parameters));
  str_len = sizeof(str);
  EXPECT_ZERO(fingera_btc_address_decode(
      "bc1qpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqpnzxff", 46, str, &str_len,
      &g_mainnet_chain_parameters));
  str_len = sizeof(str);
  EXPECT_ZERO(fingera_btc_address_decode(
      "bc17pqyqszqgpqyqszqgpqyqszqgpqyqszqg8d0gmc", 42, str, &str_len,
      &g_mainnet_chain_parameters));

  test_address("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
               "76a91465a16059864a2fdbc7c99a4723a8395bc6f188eb88ac",
               &g_mainnet_chain_parameters);
  test_address("3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou",
               "a91474f209f6ea907e2ea48f74fae05782ae8a66525787",
               &g_mainnet_chain_parameters);
  test_address("mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs",
               "76a91453c0307d6851aa0ce7825ba883c6bd9ad242b48688ac",
               &g_testnet_chain_parameters);
  test_address("mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs",
               "76a91453c0307d6851aa0ce7825ba883c6bd9ad242b48688ac",
               &g_regnet_chain_parameters);
  test_address("2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br",
               "a9146349a418fc4578d10a372b54b45c280cc8c4382f87",
               &g_testnet_chain_parameters);
  test_address("1Ax4gZtb7gAit2TivwejZHYtNNLT18PUXJ",
               "76a9146d23156cbbdcc82a5a47eee4c2c7c583c18b6bf488ac",
               &g_mainnet_chain_parameters);
  test_address("3QjYXhTkvuj8qPaXHTTWb5wjXhdsLAAWVy",
               "a914fcc5460dd6e2487c7d75b1963625da0e8f4c597587",
               &g_mainnet_chain_parameters);
  test_address("n3ZddxzLvAY9o7184TB4c6FJasAybsw4HZ",
               "76a914f1d470f9b02370fdec2e6b708b08ac431bf7a5f788ac",
               &g_testnet_chain_parameters);
  test_address("2NBFNJTktNa7GZusGbDbGKRZTxdK9VVez3n",
               "a914c579342c2c4c9220205e2cdc285617040c924a0a87",
               &g_testnet_chain_parameters);
  test_address("1C5bSj1iEGUgSTbziymG7Cn18ENQuT36vv",
               "76a9147987ccaa53d02c8873487ef919677cd3db7a691288ac",
               &g_mainnet_chain_parameters);
  test_address("3AnNxabYGoTxYiTEZwFEnerUoeFXK2Zoks",
               "a91463bcc565f9e68ee0189dd5cc67f1b0e5f02f45cb87",
               &g_mainnet_chain_parameters);
  test_address("n3LnJXCqbPjghuVs8ph9CYsAe4Sh4j97wk",
               "76a914ef66444b5b17f14e8fae6e7e19b045a78c54fd7988ac",
               &g_testnet_chain_parameters);
  test_address("2NB72XtkjpnATMggui83aEtPawyyKvnbX2o",
               "a914c3e55fceceaa4391ed2a9677f4a4d34eacd021a087",
               &g_testnet_chain_parameters);
  test_address("1Gqk4Tv79P91Cc1STQtU3s1W6277M2CVWu",
               "76a914adc1cc2081a27206fae25792f28bbc55b831549d88ac",
               &g_mainnet_chain_parameters);
  test_address("33vt8ViH5jsr115AGkW6cEmEz9MpvJSwDk",
               "a914188f91a931947eddd7432d6e614387e32b24470987",
               &g_mainnet_chain_parameters);
  test_address("mhaMcBxNh5cqXm4aTQ6EcVbKtfL6LGyK2H",
               "76a9141694f5bc1a7295b600f40018a618a6ea48eeb49888ac",
               &g_testnet_chain_parameters);
  test_address("2MxgPqX1iThW3oZVk9KoFcE5M4JpiETssVN",
               "a9143b9b3fd7a50d4f08d1a5b0f62f644fa7115ae2f387",
               &g_testnet_chain_parameters);
  test_address("1JwMWBVLtiqtscbaRHai4pqHokhFCbtoB4",
               "76a914c4c1b72491ede1eedaca00618407ee0b772cad0d88ac",
               &g_mainnet_chain_parameters);
  test_address("3QCzvfL4ZRvmJFiWWBVwxfdaNBT8EtxB5y",
               "a914f6fe69bcb548a829cce4c57bf6fff8af3a5981f987",
               &g_mainnet_chain_parameters);
  test_address("mizXiucXRCsEriQCHUkCqef9ph9qtPbZZ6",
               "76a914261f83568a098a8638844bd7aeca039d5f2352c088ac",
               &g_testnet_chain_parameters);
  test_address("2NEWDzHWwY5ZZp8CQWbB7ouNMLqCia6YRda",
               "a914e930e1834a4d234702773951d627cce82fbb5d2e87",
               &g_testnet_chain_parameters);
  test_address("19dcawoKcZdQz365WpXWMhX6QCUpR9SY4r",
               "76a9145eadaf9bb7121f0f192561a5a62f5e5f5421029288ac",
               &g_mainnet_chain_parameters);
  test_address("37Sp6Rv3y4kVd1nQ1JV5pfqXccHNyZm1x3",
               "a9143f210e7277c899c3a155cc1c90f4106cbddeec6e87",
               &g_mainnet_chain_parameters);
  test_address("myoqcgYiehufrsnnkqdqbp69dddVDMopJu",
               "76a914c8a3c2a09a298592c3e180f02487cd91ba3400b588ac",
               &g_testnet_chain_parameters);
  test_address("2N7FuwuUuoTBrDFdrAZ9KxBmtqMLxce9i1C",
               "a91499b31df7c9068d1481b596578ddbb4d3bd90baeb87",
               &g_testnet_chain_parameters);
  test_address("13p1ijLwsnrcuyqcTvJXkq2ASdXqcnEBLE",
               "76a9141ed467017f043e91ed4c44b4e8dd674db211c4e688ac",
               &g_mainnet_chain_parameters);
  test_address("3ALJH9Y951VCGcVZYAdpA3KchoP9McEj1G",
               "a9145ece0cadddc415b1980f001785947120acdb36fc87",
               &g_mainnet_chain_parameters);

  test_address(
      "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grp"
      "lx",
      "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3"
      "a323f1433bd6",
      &g_mainnet_chain_parameters);

  test_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
               "0014751e76e8199196d454941c45d1b3a323f1433bd6",
               &g_mainnet_chain_parameters);

  test_address("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
               "0014751e76e8199196d454941c45d1b3a323f1433bd6",
               &g_regnet_chain_parameters);

  test_address(
      "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
      "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
      &g_testnet_chain_parameters);

  test_address("bc1sw50qa3jx3s", "6002751e", &g_mainnet_chain_parameters);
  test_address("bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
               "5210751e76e8199196d454941c45d1b3a323",
               &g_mainnet_chain_parameters);
  test_address(
      "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
      "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
      &g_testnet_chain_parameters);
  test_address(
      "bcrt1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvseswlauz7",
      "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
      &g_regnet_chain_parameters);
}