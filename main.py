from mnemonic import Mnemonic
from bip32 import BIP32
import base64
from utils import get_chash_160


def create_wallet(testnet=False):
    testnet = False

    path = "m/44'/1'/0'/0/0" if testnet else "m/44'/0'/0'/0/0"

    mnemo = Mnemonic("english")
    words = mnemo.generate()
    seed = mnemo.to_seed(words, passphrase="")

    bip32 = BIP32.from_seed(seed)

    privkey = bip32.get_privkey_from_path(path)
    pubkey = base64.b64encode(bip32.get_pubkey_from_path(path)).decode('utf-8')
    definition = ['sig', {"pubkey": pubkey}]

    print(f"privkey: {privkey}")
    print(f"pubkey: {pubkey}")
    print(f"address: {get_chash_160(definition)}")


create_wallet()
