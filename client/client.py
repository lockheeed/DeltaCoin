import requests, hashlib, random, json, time, os, platform, datetime

import os, hashlib, binascii, base58
from ecdsa import SigningKey, VerifyingKey
from random import choice

from ecdsa import NIST521p
from ecdsa.util import randrange_from_seed__trytryagain

__version__ = "BETA 1.7.3"

banner = f"""
  /$$$$$$$  /$$$$$$$$ /$$    /$$$$$$$$ /$$$$$$         /$$$$$$            /$$
 | $$__  $$| $$_____/| $$   |__  $$__//$$__  $$       /$$__  $$          |__/
 | $$  \ $$| $$      | $$      | $$  | $$  \ $$      | $$  \__/  /$$$$$$  /$$ /$$$$$$$
 | $$  | $$| $$$$$   | $$      | $$  | $$$$$$$$      | $$       /$$__  $$| $$| $$__  $$
 | $$  | $$| $$__/   | $$      | $$  | $$__  $$      | $$      | $$  \ $$| $$| $$  \ $$
 | $$  | $$| $$      | $$      | $$  | $$  | $$      | $$    $$| $$  | $$| $$| $$  | $$
 | $$$$$$$/| $$$$$$$$| $$$$$$$$| $$  | $$  | $$      |  $$$$$$/|  $$$$$$/| $$| $$  | $$
 |_______/ |________/|________/|__/  |__/  |__/       \______/  \______/ |__/|__/  |__/
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
        url = "https://raw.githubusercontent.com/lockheeed/DeltaCoin/master/version"
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

class DeltaCoin():
    def __init__(self):
        self.curve = NIST521p
        self.hash = hashlib.sha512

    def generate_wallet(self):
        seed = os.urandom(self.curve.baselen)
        secexp = randrange_from_seed__trytryagain(seed, self.curve.order)
        priv = SigningKey.from_secret_exponent(secexp, curve=self.curve, hashfunc=self.hash)
        pub = priv.get_verifying_key()
        return self.key_to_string(pub), self.key_to_string(priv), self.pub_to_address(self.key_to_string(pub))

    def key_to_string(self, key):
        return key.to_string().hex()

    def pub_to_address(self, key):
        key_hash = b"\x0e" + hashlib.sha224(hashlib.sha512(key.encode("utf-8")).digest()).digest()
        check_sum = hashlib.sha256(key_hash).digest()[0:4]
        address = base58.b58encode(key_hash + check_sum)
        return address.decode("utf-8")

    def string_to_pub(self, pub):
        return VerifyingKey.from_string(bytearray.fromhex(pub), curve=self.curve)

    def string_to_priv(self, priv):
        return SigningKey.from_string(bytearray.fromhex(priv), curve=self.curve)

    def txn_hash(self, sender, outputs, inputs, public):
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
        hash = DeltaCoin().txn_hash(sender, outputs, inputs, public)

        data = {
            "sender":sender,
            "outputs":outputs,
            "inputs":inputs,
            "public":public,
            "hash":hash,
            "sign":DeltaCoin().string_to_priv(private).sign(hash.encode("utf-8")).hex()
               }

        try:
            response = requests.post(f"http://{self.node}/new_txn", json={"txn":data, "node":"client"})
        except requests.exceptions.ConnectionError:
            print(f" [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] {Color.f_r + Color.bold}Node ({self.node}) is down! {Color.clear}")
            if self.choice_the_node():
                return self.send_transaction(sender, recipient, amount_with_fee, return_value, fee, inputs, public, private)

        if response.status_code == 200:
            print("\n [ + ] Transaction has been sent successfully!")
        else:
            print("\n [ + ] Something went wrong! " + response.text)

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
        for node in self.nodes.copy():
            try:
                requests.get(f"http://{node}/get_blockchain_length").json()["length"]
            except requests.exceptions.ConnectionError:
                self.nodes.remove(node)

        if len(self.nodes) == 0:
            print(Color.f_r + "\n [ ! ] All nodes are dead! Update your nodes.json!" + Color.clear)
            exit()

        print(Color.f_y + " [ ~ ] Available nodes list:" + Color.clear)
        for number, host in enumerate(self.nodes):
            print(f"\t{number}: {host}")

        try:
            node_id = int(input("\n [ >> ] Choice the node: "))
            self.node = self.nodes[node_id]
        except:
            self.node = choice(self.nodes)

        print(Color.f_g + f" [ + ] Chosen node is {self.node}\n" + Color.clear)

    def load(self):
        if not os.path.isdir("cache"):
            os.mkdir("cache")

        if os.path.isfile("cache/nodes.json"):
            with open("cache/nodes.json", "r") as f:
                self.nodes = json.load(f)["nodes"]
                f.close()
        else:
            self.nodes = {}

if __name__ == '__main__':
    if platform.system() == "Windows":
        os.system("cls")
    elif platform.system() == "Linux":
        os.system("clear")

    print(banner)
    Updater.update()
    node = Node()

    while True:
        command = str(input(" >> "))
        try:
            if command == "new":
                pub, priv, addr = DeltaCoin().generate_wallet()
                print(f"\n ... Your wallet is ready ...\n [ * ] Addres: {addr}\n\n [ * ] Public Key: {pub}\n [ * ] Private Key: {priv}")

            elif command == "send":
                sender = str(input(" [ * ] Sender: "))
                public = str(input(" [ * ] Public Key: "))
                private = str(input(" [ * ] Private Key: "))
                recipient = str(input("\n [ * ] Recipient: "))
                amount = float(input(" [ * ] Amount: "))

                inputs, sum = node.get_inputs_for_txn(sender, int(amount))
                fee = round(amount / 100, 4)
                amount_with_fee = amount - fee
                return_value = sum - amount

                if inputs == {}:
                    print("\n [ - ] Извините, но кажется вы БОМЖАРИК!")
                    continue

                node.send_transaction(sender, recipient, amount_with_fee, return_value, fee, inputs, public, private)

            elif command == "balance":
                address = str(input(" [ * ] DeltaCoin address: "))
                balance = node.get_balance(address)
                print(f" [ * ] Current balance is {str(balance)} D$")

        except KeyboardInterrupt:
            print(" ")
            pass
