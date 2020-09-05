from flask import Flask, Response, request
import json, time, hashlib, requests, threading, random, os, platform, datetime, subprocess
from random import choice

import os, hashlib, binascii, base58
from ecdsa import SigningKey, VerifyingKey

from ecdsa import NIST521p
from ecdsa.util import randrange_from_seed__trytryagain

__version__ = "BETA 1.8.3"

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

class ScalingTool(object):
    def __init__(self, min, max, min_scale, max_scale):
        self.max = max
        self.min = min
        self.max_scale = max_scale
        self.min_scale = min_scale

    def scale(self, value):
        if value > self.max:
            value = self.max

        if value < self.min:
            value = 0

        slice = self.max_scale - self.min_scale
        value = (value - self.min) / (self.max - self.min)
        value *= slice
        value += self.min_scale
        return value

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

class DeltaCoin_Wallet():
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

class Blockchain(object):
    def __init__(self, nodes = None):
        self.chain = []
        self.nodes = nodes
        self.utxo = {}
        self.difficulty = 0

        self.fixed_award = 12

        self.requests_pause = 10
        self.already_decided = False
        self.pow_in_work = False

    def sync_blockchain(self):
        print(" [ ~ ] Synchronizating with nodes...", end="", flush=True)
        self.chain, self.utxo, self.difficulty = self.nodes.sync()

        if len(self.chain) < 1:
            print(Color.f_r + "NOT SUCCESSFUL\n" + Color.clear)
            exit()

        else:
            print(Color.f_g + "SUCCESSFUL\n" + Color.clear)

    @staticmethod
    def is_the_same_txn_blocks(first_txn_block, second_txn_block):
        try:
            if first_txn_block == second_txn_block:
                return True
            else:
                return False
        except TypeError:
            return False

    def new_block(self, txn_block, target, miner_address):
        self.txn_block = txn_block.copy()
        self.original_txn_block = txn_block.copy()

        self.target = target

        self.txn_block.append(self.coinfactory_reward(self.txn_block, miner_address))
        self.block = {
                "hash":None,
                "prev_hash":self.last_block["hash"],
                "index":self.last_block["index"] + 1,
                "timestamp":time.time(),
                "txns":self.txn_block,
                "merkle_root":self.get_merkle_root(self.txn_block),
                "proof":0
                     }
        if self.pow():
            print(f" [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] {Color.f_g + Color.bold}Solution for block has been founded! {Color.clear}")
        else:
            return False

        if self.nodes.send_block(self.block):
            self.chain.append(self.block)
            return True
        else:
            return False

    def coinfactory_reward(self, txn_block, miner_address):
        nonce = random.randint(0, 1000000000)
        reward = self.fixed_award + Blockchain.get_fee(txn_block)

        hash = Blockchain.coinfactory_txn_hash("COINFACTORY", [{"recipient":miner_address, "amount":reward}], nonce)
        return {
            "sender":"COINFACTORY",
            "outputs":[{"recipient":miner_address, "amount":reward}],
            "inputs":{},
            "nonce":nonce,
            "hash":hash,
            "sign":"COINFACTORY"
               }

    def pow(self):
        self.pow_in_work = True
        self.already_decided = False
        threading.Thread(target=self.__mining_speed, daemon=True).start()
        threading.Thread(target=self.__checking_txn_blocks ,daemon=True).start()
        while int(self.hash_block(self.block), 16) > int(self.target, 16) and not self.already_decided:
            self.block["proof"] += 1
        self.pow_in_work = False
        if self.already_decided:
            print(f" [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] {Color.f_y + Color.bold}Block already decided! Stoping mining process... {Color.clear}")
            self.pow_in_work = False
            return False
        self.block["hash"] = self.hash_block(self.block)
        return True

    def __checking_txn_blocks(self):
        old_block_index = self.block["index"]
        current_block_index = self.nodes.get_blockchain_length()
        while old_block_index == current_block_index:
            time.sleep(blockchain.requests_pause)
            current_block_index = self.nodes.get_blockchain_length()
        self.already_decided = True

    def __mining_speed(self):
        old_block_index = self.block["index"]
        last_proof_value = 0
        while old_block_index == self.block["index"]:
            if self.block["proof"] != 0:
                speed = (self.block["proof"] - last_proof_value) / 5
                last_proof_value = self.block["proof"]

                if speed < 1000:
                    out = str(round(speed, 3)) + " H/sec"
                if speed >= 1000:
                    out = str(round(speed / 1000, 3)) + " KH/sec"
                if speed >= 1000000:
                    out = str(round(speed / 1000000, 3)) + " MH/sec"
                if self.pow_in_work:
                    print(f" [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] Current mining speed is {out}")

            time.sleep(5)

    @staticmethod
    def gen_target(difficulty, place_size = 12, init_zeros_count = 6):
        if difficulty > 10 * place_size:
            difficulty = 10 * place_size

        if difficulty < 0:
            difficulty = 0

        if difficulty > place_size * 10:
            return None

        else:
            place = int(difficulty // 10)
            maximum_possible_bytes = int("f" * (place_size - place), 16)
            subtrahend = int(round(maximum_possible_bytes / 10 * (difficulty - place * 10), 1))
            normalized = maximum_possible_bytes - subtrahend
            if normalized < maximum_possible_bytes / 16:
                normalized = int(maximum_possible_bytes / 16) + 1
            bits = "0" * place + hex(normalized)[2:]

        target = "0" * init_zeros_count + bits + "f" * (64 - (init_zeros_count + len(bits)))
        return target

    @staticmethod
    def difficulty_recalculation(chain, scaler, difficulty, part, needed = 420):
        current_mining_time = (chain[-1]["timestamp"] - chain[-part]["timestamp"]) / part

        if current_mining_time > needed + 60:
            k = current_mining_time / needed
            difficulty -= scaler.scale(k)
            if difficulty < 1:
                difficulty = 1

        elif needed > current_mining_time - 60:
            k = needed / current_mining_time
            difficulty += scaler.scale(k)

        return difficulty

    @staticmethod
    def txn_hash(sender, outputs, inputs, public):
        return hashlib.sha256(bytes(sender + str(outputs) + json.dumps(inputs, sort_keys=True) + public, "utf-8")).hexdigest()

    @staticmethod
    def coinfactory_txn_hash(sender, outputs, nonce):
        return hashlib.sha256(bytes(sender + str(outputs) + str(nonce), "utf-8")).hexdigest()

    @staticmethod
    def is_a_valid_txn(txn, utxo):
        actual_hash = Blockchain.txn_hash(txn["sender"], txn["outputs"],  txn["inputs"],  txn["public"])
        if DeltaCoin_Wallet().pub_to_address(txn["public"]) == txn["sender"] and txn["hash"] == actual_hash and \
        DeltaCoin_Wallet().string_to_pub(txn["public"]).verify(bytearray.fromhex(txn["sign"]), txn["hash"].encode("utf-8")) and \
        Blockchain.get_sum_of_inputs(txn["inputs"], txn["sender"], utxo) >= Blockchain.get_sum_of_outputs(txn["outputs"]):
            return True
        else:
            return False

    @staticmethod
    def get_sum_of_inputs(inputs, address, utxo):
        sum = 0
        if len(inputs) > 0:
            for inp in inputs:
                if inp in utxo[address]:
                    sum += inp[0]
                else:
                    break
        return sum

    @staticmethod
    def get_sum_of_outputs(outputs):
        sum = 0
        if len(outputs) > 0:
            for element in outputs:
                if type(element) == dict:
                    sum += element["amount"]
                elif  type(element) == float:
                    sum += element
        return sum

    @staticmethod
    def utxo_recalculation(txn, utxo):
        try:
            if txn["sender"] != "COINFACTORY":
                if Blockchain.is_a_valid_txn(txn, utxo):
                    for inp in txn["inputs"]:
                        del utxo[txn["sender"]][utxo[txn["sender"]].index(inp)]
                    for inputs, address in utxo.copy().items():
                        if len(inputs) == 0:
                            del utxo[txn["sender"]]
                else:
                    return False
            return True
        except KeyError:
            return False

    @staticmethod
    def is_a_valid_blockchain(blockchain):
        utxo = {}
        scaler = ScalingTool(0, 10, 0, 9)
        difficulty = 0
        for block in blockchain:
            if block['index'] > 0:
                if block["index"] != blockchain.index(block):
                    return False, {}, 0

                if int(block["hash"], 16) > int(Blockchain.gen_target(difficulty), 16):
                    return False, {}, 0

                if Blockchain.get_count_of_coinfactory_txns(block["txns"]) > 1 or Blockchain.get_fee(block["txns"]) + Blockchain().fixed_award < Blockchain.get_coinfactory_out(block["txns"]):
                    return False, {}, 0

                if block["hash"] != Blockchain.hash_block(block):
                    return False, {}, 0

                if block["merkle_root"] != Blockchain.get_merkle_root(block["txns"]):
                    return False, {}, 0

                for txn in block["txns"]:
                    if not Blockchain.utxo_recalculation(txn, utxo):
                        return False, {}, 0

                for txn in block["txns"]:
                    for element in txn["outputs"]:
                        if type(element) == dict:
                            if element["recipient"] not in utxo:
                                utxo[element["recipient"]] = [ [element["amount"], block["index"], txn["hash"]] ]
                            else:
                                utxo[element["recipient"]].append([element["amount"], block["index"], txn["hash"]])

                if (block["index"]) % 5 == 0:
                    difficulty = Blockchain.difficulty_recalculation(blockchain, scaler, difficulty, 5)

        return True, utxo, difficulty

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def get_coinfactory_out(txn_block):
        out = 0
        for txn in txn_block:
            if txn["sender"] == "COINFACTORY":
                for element in txn["outputs"]:
                    if type(element) == dict:
                        out += element["amount"]
                    elif  type(element) == float:
                        out += element
        return out

    @staticmethod
    def get_fee(txn_block):
        fee = 0
        for txn in txn_block:
            for element in txn["outputs"]:
                if type(element) == float:
                    fee += element
        return fee

    @staticmethod
    def get_count_of_coinfactory_txns(txn_block):
        count = 0
        for txn in txn_block:
            if txn["sender"] == "COINFACTORY":
                count += 1
        return count

    @staticmethod
    def get_merkle_root(txn_block):
        merkle_root = txn_block[0]["hash"]
        for txn in txn_block[1:]:
            merkle_root = hashlib.sha256(merkle_root.encode("utf-8") + txn["hash"].encode("utf-8")).hexdigest()
        return merkle_root

    @staticmethod
    def hash_block(block):
        temp = block.copy()
        del temp["hash"]
        block_string = json.dumps(temp, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class Nodes(object):
    def __init__(self):
        self.load()
        self.choice_the_node()

    def sync(self):
        try:
            length = requests.get(f"http://{self.node}/get_blockchain_length", timeout=1).json()["length"]
        except requests.exceptions.ConnectionError:
            return [], {}

        try:
            blockchain = requests.get(f"http://{self.node}/get_blockchain", timeout=1).json()["blockchain"]
        except requests.exceptions.ConnectionError:
            return [], {}

        is_valid, utxo, difficulty = Blockchain.is_a_valid_blockchain(blockchain)
        if length == len(blockchain) and is_valid:
            return blockchain, utxo, difficulty

        else:
            return [], {}, 0

    def get_txn_block(self):
        try:
            response = requests.get(f"http://{self.node}/get_txn_block").json()
            txn_block = response["txn_block"]
            target = response["target"]
        except requests.exceptions.ConnectionError:
            print(f"\n [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] {Color.f_r + Color.bold}Node ({self.node}) is down! {Color.clear}")
            if self.choice_the_node():
                return self.get_txn_block()

        return txn_block, target

    def get_block(self, index):
        try:
            block = requests.get(f"http://{self.node}/get_block", params={"index":index}).json()["block"]
        except requests.exceptions.ConnectionError:
            print(f"\n [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] {Color.f_r + Color.bold}Node ({self.node}) is down! {Color.clear}")
            if self.choice_the_node():
                return self.get_block(index)
        return block

    def send_block(self, block):
        try:
            response = requests.post(f"http://{self.node}/new_block", json={"block":block,"node":"miner"})
            if response.status_code == 200:
                print(f" [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] {Color.f_g + Color.bold}Node accepted block solution!{Color.clear}")
                return True
            else:
                print(f" [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] {Color.f_r + Color.bold}Node rejected block solution! {response.text}{Color.clear}")
                return False
        except requests.exceptions.ConnectionError:
            print(f"\n [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] {Color.f_r + Color.bold}Node ({self.node}) is down! {Color.clear}")
            if self.choice_the_node():
                return self.send_block(block)

    def get_blockchain(self):
        try:
            return requests.get(f"http://{self.node}/get_blockchain").json()["blockchain"]
        except requests.exceptions.ConnectionError:
            print(f"\n [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] {Color.f_r + Color.bold}Node ({self.node}) is down! {Color.clear}")
            if self.choice_the_node():
                return self.get_blockchain()

    def get_blockchain_length(self):
        try:
            return requests.get(f"http://{self.node}/get_blockchain_length").json()["length"]
        except requests.exceptions.ConnectionError:
            print(f"\n [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] {Color.f_r + Color.bold}Node ({self.node}) is down! {Color.clear}")
            if self.choice_the_node():
                return self.get_blockchain_length()

    def choice_the_node(self):
        self.load()
        for node in self.nodes.copy():
            try:
                requests.get(f"http://{node}/get_blockchain_length").json()["length"]
            except requests.exceptions.ConnectionError:
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
            self.nodes = {}

if __name__ == '__main__':
    if platform.system() == "Windows":
        os.system("cls")
    elif platform.system() == "Linux":
        os.system("clear")

    print(banner)
    Updater.update()
    nodes = Nodes()

    blockchain = Blockchain(nodes)
    blockchain.sync_blockchain()

    miner_address = input(" [ * ] Enter your DeltaCoin address: ")

    print(" ")
    while True:
        print(f" [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] Trying to get transaction block...")

        while True:
            txn_block, target = nodes.get_txn_block()
            length = nodes.get_blockchain_length()
            if length > len(blockchain.chain):
                for i in range(blockchain.last_block["index"] + 1, length):
                    blockchain.chain.append(nodes.get_block(i))
            if type(txn_block) == list:
                print(f"\n [ {Color.bold + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + Color.clear} ] {Color.f_y + Color.bold}New transaction block has been founded! Starting mining process...{Color.clear}")
                blockchain.new_block(txn_block, target, miner_address)
                break

            else:
                time.sleep(blockchain.requests_pause)
