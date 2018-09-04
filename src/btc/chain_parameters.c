#include <fingera_libc/btc/chain_parameters.h>

chain_parameters g_mainnet_chain_parameters = {
    .prefix_pubkey_address = "\x00",
    .prefix_pubkey_address_size = 1,

    .prefix_script_address = "\x05",
    .prefix_script_address_size = 1,

    .prefix_secret_key = "\x80",
    .prefix_secret_key_size = 1,

    .prefix_ext_public_key = "\x04\x88\xB2\x1E",
    .prefix_ext_public_key_size = 4,

    .prefix_ext_secret_key = "\x04\x88\xAD\xE4",
    .prefix_ext_secret_key_size = 4,

    .bech32_hrp = "bc",
    .bech32_hrp_size = 2,
};

chain_parameters g_testnet_chain_parameters = {
    .prefix_pubkey_address = "\x6F",
    .prefix_pubkey_address_size = 1,

    .prefix_script_address = "\xC4",
    .prefix_script_address_size = 1,

    .prefix_secret_key = "\xEF",
    .prefix_secret_key_size = 1,

    .prefix_ext_public_key = "\x04\x35\x87\xCF",
    .prefix_ext_public_key_size = 4,

    .prefix_ext_secret_key = "\x04\x35\x83\x94",
    .prefix_ext_secret_key_size = 4,

    .bech32_hrp = "tb",
    .bech32_hrp_size = 2,
};

chain_parameters g_regnet_chain_parameters = {
    .prefix_pubkey_address = "\x6F",
    .prefix_pubkey_address_size = 1,

    .prefix_script_address = "\xC4",
    .prefix_script_address_size = 1,

    .prefix_secret_key = "\xEF",
    .prefix_secret_key_size = 1,

    .prefix_ext_public_key = "\x04\x35\x87\xCF",
    .prefix_ext_public_key_size = 4,

    .prefix_ext_secret_key = "\x04\x35\x83\x94",
    .prefix_ext_secret_key_size = 4,

    .bech32_hrp = "bcrt",
    .bech32_hrp_size = 4,
};