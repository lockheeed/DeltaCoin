import requests, hashlib, random, json, time, os, platform, datetime, subprocess

import os, hashlib, binascii, base58
from ecdsa import SigningKey, VerifyingKey
from random import choice

from ecdsa import NIST521p
from ecdsa.util import randrange_from_seed__trytryagain

__version__ = "BETA 2.1.2"

banner = f"""
 /$$$$$$$$ /$$                        /$$$$$$   /$$$$$$  /$$$$$$ /$$   /$$
|__  $$__/| $$                       /$$__  $$ /$$__  $$|_  $$_/| $$$ | $$
   | $$   | $$$$$$$   /$$$$$$       | $$  \__/| $$  \ $$  | $$  | $$$$| $$
   | $$   | $$__  $$ /$$__  $$      | $$      | $$  | $$  | $$  | $$ $$ $$
   | $$   | $$  \ $$| $$$$$$$$      | $$      | $$  | $$  | $$  | $$  $$$$
   | $$   | $$  | $$| $$_____/      | $$    $$| $$  | $$  | $$  | $$\  $$$
   | $$   | $$  | $$|  $$$$$$$      |  $$$$$$/|  $$$$$$/ /$$$$$$| $$ \  $$
   |__/   |__/  |__/ \_______/       \______/  \______/ |______/|__/  \__/
 [ * ] Version: {__version__}
"""

class Color(object):
    clear = "\x1b[0m"
    bold = "\x1b[1m"
    underlined = "\x1b[4m"

    f_bk = "\x1b[30m"
    f_r = "\x1b[31m"
    f_g = "\x1b[32m"
    f_y = "\x1b[33m"
    f_be = "\x1b[34m"

    g_bk = "\x1b[40m"
    g_r = "\x1b[41m"
    g_g = "\x1b[42m"
    g_y = "\x1b[43m"
    g_be = "\x1b[44m"

class Updater(object):
    def __init__(self):
        pass

    @staticmethod
    def update():
        print(Color.bold + " [ ~ ] Checking for updates...", end="", flush=True)
        url = "https://raw.githubusercontent.com/lockheeed/TheCoin/master/version"
        try:
            if requests.get(url, timeout=7).text.strip() == __version__:
                print(Color.f_g + "UP TO DATE" + Color.clear)
            else:
                print(Color.f_r + "UPDATE NEEDED" + Color.clear)
                if subprocess.run(["git", "pull"]).returncode == 0:
                    print(Color.f_g + "\n [ + ] Update completed! Now you need to restart this script!" + Color.clear)
                    exit()

        except requests.exceptions.ConnectionError:
            print(Color.f_r + "OFFLINE" + Color.clear)
            exit()

class TheCoin_Wallet():
    def __init__(self):
        self.curve = NIST521p
        self.hash = hashlib.sha512

    def generate_wallet(self):
        seed = os.urandom(self.curve.baselen)
        secexp = randrange_from_seed__trytryagain(seed, self.curve.order)
        priv = SigningKey.from_secret_exponent(secexp, curve=self.curve, hashfunc=self.hash)
        pub = priv.get_verifying_key()
        return self.key_to_string(pub), self.key_to_string(priv), self.pub_to_address(self.key_to_string(pub))

    @staticmethod
    def key_to_string(key):
        return key.to_string().hex()

    @staticmethod
    def pub_to_address(key):
        key_hash = b"\x0e" + hashlib.sha224(hashlib.sha512(key.encode("utf-8")).digest()).digest()
        check_sum = hashlib.sha256(key_hash).digest()[0:4]
        address = base58.b58encode(key_hash + check_sum)
        return address.decode("utf-8")

    def string_to_pub(self, pub):
        return VerifyingKey.from_string(bytearray.fromhex(pub), curve=self.curve)

    def string_to_priv(self, priv):
        return SigningKey.from_string(bytearray.fromhex(priv), curve=self.curve)

    @staticmethod
    def is_a_valid_address(address):
        if type(address) == str:
            if len(address) == 45 and address[:1] == "5" and len([symbol for symbol in address if symbol not in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"]) == 0:
                return True
            else:
                return False
        elif type(address) == dict:
            for addr in address:
                if len(addr) != 45 or addr[:1] != "5" or len([symbol for symbol in addr if symbol not in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"]) > 0:
                    return False
            return True

    @staticmethod
    def txn_hash(sender, outputs, inputs, public):
        return hashlib.sha256(bytes(sender + str(outputs) + json.dumps(inputs, sort_keys=True) + public, "utf-8")).hexdigest()

class Node(object):
    def __init__(self):
        self.load()
        self.choice_the_node()

    def send_transaction(self, sender, recipient, amount_with_fee, return_value, fee, inputs, public, private):
        if return_value > 0:
            outputs = [{"amount":amount_with_fee, "recipient":recipient}, {"amount":return_value, "recipient":sender}, fee]
        else:
            outputs = [{"amount":amount_with_fee, "recipient":recipient}, fee]
        hash = TheCoin_Wallet().txn_hash(sender, outputs, inputs, public)

        data = {
            "sender":sender,
            "outputs":outputs,
            "inputs":inputs,
            "public":public,
            "hash":hash,
            "sign":TheCoin_Wallet().string_to_priv(private).sign(hash.encode("utf-8")).hex()
               }

        try:
            response = requests.post(f"http://{self.node}/new_txn", json={"txn":data, "node":"client"})
        except requests.exceptions.ConnectionError:
            print(f"\n [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] {Color.f_r + Color.bold}Node ({self.node}) is down! {Color.clear}")
            if self.choice_the_node():
                return self.send_transaction(sender, recipient, amount_with_fee, return_value, fee, inputs, public, private)

        if response.status_code == 200:
            print(Color.f_g + "\n [ + ] Transaction has been sent successfully!" + Color.clear)
        else:
            print(Color.f_r + "\n [ - ] Something went wrong! " + response.text + Color.clear)

    def get_balance(self, address):
        try:
            inputs = requests.get(f"http://{self.node}/get_inp", params={"address":address}).json()["utxo"]
        except requests.exceptions.ConnectionError:
            print(f" [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] {Color.f_r + Color.bold}Node ({self.node}) is down! {Color.clear}")
            if self.choice_the_node():
                return self.get_balance(address)

        balance = 0
        if len(inputs) > 0:
            for inp in inputs:
                balance += inp[0]

        return balance

    def get_inputs_for_txn(self, address, amount):
        result = {}
        try:
            inputs = requests.get(f"http://{self.node}/get_inp", params={"address":address}).json()["utxo"]
        except requests.exceptions.ConnectionError:
            print(f" [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] {Color.f_r + Color.bold}Node ({self.node}) is down! {Color.clear}")
            if self.choice_the_node():
                return self.get_inputs_for_txn(address, amount)

        if len(inputs) > 0:
            inputs.sort()

            sum_of_inputs = 0

            for i in range(0, len(inputs)):
                sum_of_inputs += inputs[i][0]
                if sum_of_inputs >= amount:
                    break

            if sum_of_inputs >= amount:
                inputs = inputs[: i + 1]
                return inputs, sum_of_inputs
            else:
                return [], 0

        return [], 0

    def choice_the_node(self):
        self.load()
        for node in self.nodes.copy():
            try:
                requests.get(f"http://{node}/get_blockchain_length", timeout=1).json()["length"]
            except:
                self.nodes.remove(node)

        if len(self.nodes) == 0:
            print(Color.f_r + "\n [ ! ] All nodes are dead! Update your nodes.json!" + Color.clear)
            exit()

        print(Color.f_y + "\n [ ~ ] Available nodes list:" + Color.clear)
        for number, host in enumerate(self.nodes):
            print(f"\t{number}: {host}")

        try:
            node_id = int(input("\n [ >> ] Choice the node: "))
            self.node = self.nodes[node_id]
        except:
            self.node = choice(self.nodes)

        print(Color.f_g + f" [ + ] Chosen node is {self.node}\n" + Color.clear)
        return True

    def load(self):
        if not os.path.isdir("cache"):
            os.mkdir("cache")

        if os.path.isfile("cache/nodes.json"):
            with open("cache/nodes.json", "r") as f:
                self.nodes = json.load(f)["nodes"]
                f.close()
        else:
            print(Color.f_r + " [ ! ] File 'cache/nodes.json' doesn't exist! Reload repository!" + Color.clear)
            exit()

if __name__ == '__main__':
    if platform.system() == "Windows":
        os.system("cls")
    elif platform.system() == "Linux":
        os.system("clear")

    print(banner)
    Updater.update()
    node = Node()

    while True:
        try:
            command = str(input(" >> ")).lower().strip()
            try:
                if command == "help":
                    out = """\n [ * ] Available command:
    \t new - create new TheCoin wallet
    \t send - create transaction (send coins)
    \t balance - check balance by TheCoin address"""
                    print(out)

                elif command == "new":
                    pub, priv, addr = TheCoin_Wallet().generate_wallet()
                    print(f"\n ... Your wallet is ready ...\n [ * ] Addres: {addr}\n\n [ * ] Public Key: {pub}\n [ * ] Private Key: {priv}")

                elif command == "send":
                    sender = str(input(" [ * ] Sender TheCoin address: ")).replace(" ", "")
                    if not TheCoin_Wallet.is_a_valid_address(sender):
                        print(Color.f_r + " [ ! ] Invalid address format! Is it TheCoin address?\n" + Color.clear)
                        continue

                    public = str(input(" [ * ] Public Key: "))
                    private = str(input(" [ * ] Private Key: "))
                    recipient = str(input("\n [ * ] Recipient: ")).replace(" ", "")
                    if not TheCoin_Wallet.is_a_valid_address(recipient):
                        print(Color.f_r + " [ ! ] Invalid address format! Is it TheCoin address?\n" + Color.clear)
                        continue

                    amount = float(input(" [ * ] Amount: "))

                    inputs, sum = node.get_inputs_for_txn(sender, int(amount))
                    fee = round(amount / 100, 4)
                    amount_with_fee = amount - fee
                    return_value = sum - amount

                    if sum < amount:
                        print(Color.f_r + "\n [ - ] You don't have enough coins for this transaction!" + Color.clear)
                        continue

                    node.send_transaction(sender, recipient, amount_with_fee, return_value, fee, inputs, public, private)

                elif command == "balance":
                    address = str(input(" [ * ] TheCoin address: ")).replace(" ", "")
                    if not TheCoin_Wallet.is_a_valid_address(address):
                        print(Color.f_r + " [ ! ] Invalid address format! Is it TheCoin address?\n" + Color.clear)
                        continue

                    balance = node.get_balance(address)
                    print(f" [ * ] Current balance is {Color.f_g + str(balance) + Color.clear} TC")

                else:
                    print(Color.f_r + "\n [ ! ] Invalid command! Type 'help' for display available commands.\n" + Color.clear)

            except KeyboardInterrupt:
                print(" ")
                pass

        except KeyboardInterrupt:
            print(Color.f_r + " \n\n[ ! ] Keyboard Interrupt!" + Color.clear)
            exit()
