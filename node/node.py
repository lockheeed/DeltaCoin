from flask import Flask, Response, request
from uuid import uuid4
from numpy import mean
import json, time, requests, threading, platform, socket

import os, hashlib, binascii, base58, subprocess
from ecdsa import SigningKey, VerifyingKey

from ecdsa import NIST521p
from ecdsa.util import randrange_from_seed__trytryagain

__version__ = "BETA 1.7.9"

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

class DeltaCoin_Wallet(object):
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
        self.not_distributed_txns = []
        self.txn_blocks = []
        self.utxo = {}
        self.fixed_award = 50

        self.nodes = nodes

        self.k = 1
        self.difficulty = 0

        self.scaler = ScalingTool(0, 10, 0, 9)

        threading.Thread(target=self.__distributor).start()

    def sync_blockchain(self):
        print(" [ ~ ] Synchronizating with nodes...", end="", flush=True)
        self.chain, flow, self.utxo, self.difficulty = self.nodes.sync()
        if flow:
            self.not_distributed_txns = flow["not_distributed_txns"]
            self.txn_block = flow["txn_blocks"]
            self.k = flow["k"]

        if len(self.chain) < 2 or not flow:
            print(Color.f_r + "NOT SUCCESSFUL" + Color.clear)
            ans = input(Color.f_y + "\n [ ! ] Can't get correct blockchain from known nodes. You can exit and try to change nodes list (n) or create or own blockchain (y): " + Color.clear)
            if ans.lower() == "y":
                print("\n [ ~ ] Creating blockchain...", end="", flush=True)
                self.make_genesis_block()
                self.make_dummy_txn_blocks(30)
                print(Color.f_g + "SUCCESSFUL" + Color.clear)
            else:
                exit()
        else:
            print(Color.f_g + "SUCCESSFUL" + Color.clear)

    def new_txn_block(self, length):
        self.txn_blocks.append(self.not_distributed_txns[:length])
        self.not_distributed_txns = self.not_distributed_txns[length:]

    def del_fisrt_txn_block(self):
        try:
            del self.txn_blocks[0]
        except IndexError:
            return False
        else:
            return True

    def new_txn(self, txn):
        self.not_distributed_txns.append(txn)
        for inp in txn["inputs"]:
            del self.utxo[txn["sender"]][self.utxo[txn["sender"]].index(inp)]

        for inputs, address in self.utxo.copy().items():
            if len(inputs) == 0:
                del self.utxo[txn["sender"]]

    def new_block(self, block):
        self.chain.append(block)

    def make_genesis_block(self):
        self.chain = []
        self.chain.append({
            "hash":"0"*64,
            "index":0,
            "timestamp":time.time(),
                })

    def make_dummy_txn_blocks(self, count):
        for i in range(count):
            self.txn_blocks.append([])

    def get_txn(self, block, txn_hash):
        try:
            block = blockchain.chain[int(block)]
            for txn in block["txns"]:
                if txn["hash"] == txn_hash:
                    return txn
        except KeyError:
            pass
        return {}

    @staticmethod
    def txn_hash(sender, outputs, inputs, public):
        return hashlib.sha256(bytes(sender + str(outputs) + json.dumps(inputs, sort_keys=True) + public, "utf-8")).hexdigest()

    @staticmethod
    def gen_target(difficulty, place_size = 12, init_zeros_count = 4):
        if difficulty > 10 * place_size:
            difficulty = 10 * place_size

        if difficulty < 1:
            difficulty = 1

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
    def get_sum_of_inputs(inputs, address, utxo):
        sum = 0
        if len(inputs) > 0:
            for inp in inputs:
                if inp in utxo[address]:
                    sum += inp[0]
                else:
                    print("not in :(")
                    break
        return sum

    @staticmethod
    def is_a_valid_txn(txn, utxo):
        actual_hash = Blockchain.txn_hash(txn["sender"], txn["outputs"],  txn["inputs"],  txn["public"])
        if DeltaCoin_Wallet().pub_to_address(txn["public"]) == txn["sender"] and txn["hash"] == actual_hash and \
        DeltaCoin_Wallet().string_to_pub(txn["public"]).verify(bytearray.fromhex(txn["sign"]), txn["hash"].encode("utf-8")) and \
        Blockchain.get_sum_of_inputs(txn["inputs"], txn["sender"], utxo) >= Blockchain.get_sum_of_outputs(txn["outputs"]):
            return True
        else:
            if not DeltaCoin_Wallet().pub_to_address(txn["public"]) == txn["sender"]:
                print("keys")
            elif not DeltaCoin_Wallet().string_to_pub(txn["public"]).verify(bytearray.fromhex(txn["sign"]), txn["hash"].encode("utf-8")):
                print("sign")
            elif not txn["hash"] == actual_hash:
                print("hash")
            elif not Blockchain.get_sum_of_inputs(txn["inputs"], txn["sender"], utxo) >= Blockchain.get_sum_of_outputs(txn["outputs"]):
                print("amount")

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
    def is_a_valid_blockchain(blockchain):
        utxo = {}
        scaler = ScalingTool(0, 10, 0, 9)
        difficulty = 0
        for block in blockchain:
            if block['index'] > 0:
                if block["index"] != blockchain.index(block):
                    return False, {}, 0

                if int(block["hash"], 16) > int(Blockchain.gen_target(difficulty), 16):
                    print(int(block["hash"], 16), int(Blockchain.gen_target(difficulty), 16))
                    return False, {}, 0

                if Blockchain.get_count_of_coinfactory_txns(block["txns"]) > 1 or Blockchain.get_fee(block["txns"]) + Blockchain().fixed_award < Blockchain.get_coinfactory_out(block["txns"]):
                    return False, {}, 0

                if block["hash"] != Blockchain.hash_block(block):
                    return False, {}, 0

                if block["merkle_root"] != Blockchain.get_merkle_root(block["txns"]):
                    return False, {}, 0

                for txn in block["txns"]:
                    if txn["sender"] != "COINFACTORY":
                        if Blockchain.is_a_valid_txn(txn, utxo):
                            for inp in txn["inputs"]:
                                del utxo[txn["sender"]][utxo[txn["sender"]].index(inp)]
                            for inputs, address in utxo.copy().items():
                                if len(inputs) == 0:
                                    del utxo[txn["sender"]]
                        else:
                            return False, {}, 0

                    for element in txn["outputs"]:
                        if type(element) == dict:
                            if element["recipient"] not in utxo:
                                utxo[element["recipient"]] = [ [element["amount"], block["index"], txn["hash"]] ]
                            else:
                                utxo[element["recipient"]].append([element["amount"], block["index"], txn["hash"]])

                if (block["index"] + 1) % 5 == 0:
                    difficulty = Blockchain.difficulty_recalculation(blockchain, scaler, difficulty, 5)

        return True, utxo, difficulty

    @property
    def last_block(self):
        return self.chain[-1]

    @property
    def fisrt_txn_block(self):
        try:
            return self.txn_blocks[0]
        except IndexError:
            return None

    @staticmethod
    def get_merkle_root(txn_block):
        merkle_root = txn_block[0]["hash"]
        for txn in txn_block[1:]:
            merkle_root = hashlib.sha256(merkle_root.encode("utf-8") + txn["hash"].encode("utf-8")).hexdigest()
        return merkle_root

    @staticmethod
    def hash_block(block):
        # Мы должны убедиться в том, что словарь упорядочен, иначе у нас будут непоследовательные хеши
        temp = block.copy()
        del temp["hash"]
        block_string = json.dumps(temp, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def __distributor(self):
        while True:
            if len(self.not_distributed_txns):
                if len(self.txn_blocks) > 0:
                    k = int(len(self.not_distributed_txns) / (len(self.txn_blocks) - 0.5 ))
                else:
                    k = len(self.not_distributed_txns)
                if k > 0:
                    self.new_txn_block(k)
            time.sleep(3)

    def save(self):
        try:
            if not os.path.isdir("cache"):
                os.mkdir("cache")
            with open("cache/blockchain.json", "w") as f:
                data = {"chain": self.chain,
                        "not_distributed_txns": self.not_distributed_txns,
                        "txn_blocks": self.txn_blocks,
                        }

                json.dump(data, f)
                f.close()

        except Exception as e:
            print(Color.f_r + f" [ ! ] Can't save blockchain! {str(e)}" + Color.clear)

    def load(self):
        pass

class Nodes(object):
    def __init__(self, port):
        self.port = port
        self.nodes = {}
        self.load()
        print(f" [ ~ ] Current node UID: {self.uuid}")
        self.send_self_info()
        self.save()

    def sync(self):
        temp = {}
        for uuid, host in self.nodes.copy().items():
            try:
                length = requests.get(f"http://{host}/get_blockchain_length", timeout=1).json()["length"]
            except requests.exceptions.ConnectionError:
                del self.nodes[uuid]
                continue
            temp[uuid] = length
        correct_blockchain = False
        correct_flow = False
        while not correct_blockchain or not correct_flow:
            if len(temp) != 0:
                node_with_biggest_chain = max(temp, key=temp.get)
                try:
                    blockchain = requests.get(f"http://{self.nodes[node_with_biggest_chain]}/get_blockchain").json()["blockchain"]
                    flow = requests.get(f"http://{self.nodes[node_with_biggest_chain]}/get_txn_flow").json()
                except requests.exceptions.ConnectionError:
                    del self.nodes[uuid]
                    continue

                is_valid, utxo, difficulty = Blockchain.is_a_valid_blockchain(blockchain)
                if temp[node_with_biggest_chain] == len(blockchain) and is_valid:
                    correct_blockchain = True
                    has_zero_blocks = False

                    for block in flow["txn_blocks"]:
                        if len(block) == 0:
                            has_zero_blocks = True
                            break

                        for txn in block:
                            if Blockchain.is_a_valid_txn(txn, utxo):
                                pass
                            else:
                                del temp[node_with_biggest_chain]
                                continue

                    if has_zero_blocks:
                        del temp[node_with_biggest_chain]
                        continue

                    for txn in flow["not_distributed_txns"]:
                        if Blockchain.is_a_valid_txn(txn, utxo):
                            pass
                        else:
                            del temp[node_with_biggest_chain]
                            continue
                    correct_flow = True
                    break

                else:
                    del temp[node_with_biggest_chain]
            else:
                return [], {}, {}, 0

        return blockchain, flow, utxo, difficulty

    def new_node(self, uuid, port, ip):
        ips = [host.split(":")[0] for host in self.nodes.values()]
        doubles = [ip for ip in ips if ips.count(ip) > 1]

        if uuid not in self.nodes and len(doubles) == 0 and len(uuid) == 32:
            self.nodes[uuid] = f"{ip}:{port}"
            self.save()

    def send_self_info(self):
        for host in self.nodes["nodes"]:
            try:
                node_uuid = requests.post(f"http://{host}/new_node", json={"uuid":self.uuid, "port":self.port}, timeout=1.5).text
                if len(node_uuid) == 32 and node_uuid not in self.nodes:
                    self.nodes[node_uuid] = host
            except requests.exceptions.ConnectTimeout:
                pass
        del self.nodes["nodes"]

    def send_txn(self, txn, exception=None):
        for uuid, host in self.nodes.copy().items():
            try:
                if uuid != exception:
                    requests.post(f"http://{host}/new_txn", json={"txn":txn, "node":self.uuid}, timeout=1.5)
            except requests.exceptions.ConnectTimeout:
                del self.nodes[uuid]

    def send_block(self, block, exception=None):
        for uuid, host in self.nodes.copy().items():
            try:
                if uuid != exception:
                    requests.post(f"http://{host}/new_block", json={"block":block, "node":self.uuid}, timeout=1.5)
            except requests.exceptions.ConnectTimeout:
                del self.nodes[uuid]

    def load(self):
        if not os.path.isdir("cache"):
            os.mkdir("cache")

        self.uuid = uuid4().hex

        if os.path.isfile("cache/nodes.json"):
            with open("cache/nodes.json", "r") as f:
                self.nodes["nodes"] = json.load(f)["nodes"]
                f.close()
        else:
            self.nodes = {}

    def save(self):
        if not os.path.isdir("cache"):
            os.mkdir("cache")

        with open("cache/nodes.json", "w") as f:
            nodes = []
            for key, value in self.nodes.copy().items():
                nodes.append(value)
            json.dump({"nodes":nodes}, f)
            f.close()

app = Flask(__name__)

@app.route('/new_txn', methods=['POST'])
def new_txn():
    data = request.get_json()
    txn = data["txn"]
    node = data["node"]

    if blockchain.is_a_valid_txn(txn, blockchain.utxo):
        blockchain.new_txn(txn)
        nodes.send_txn(txn, node)
        return Response("OK", status=200)
    else:
        return Response(f"Invalid txn. Check your client version! {__version__}", status=400)

@app.route('/new_block', methods=['POST'])
def new_block():
    data = request.get_json()
    block = data['block']
    node = data['node']

    #timestamp

    if int(block["hash"], 16) > int(Blockchain.gen_target(blockchain.difficulty), 16):
        return Response("Invalid block target!", status=400)

    if Blockchain.get_count_of_coinfactory_txns(block["txns"]) > 1 or Blockchain.get_fee(block["txns"]) + blockchain.fixed_award < Blockchain.get_coinfactory_out(block["txns"]):
        return Response("Invalid COINFACTORY txns!", status=400)

    if block["index"] != blockchain.last_block["index"] + 1:
        return Response("Invalid index!", status=400)

    if block["hash"] != blockchain.hash_block(block):
        return Response("Invalid block hash!", status=400)

    if block["merkle_root"] != blockchain.get_merkle_root(block["txns"]):
        return Response("Invalid merkle root!", status=400)

    for txn in block["txns"]:
        if txn["sender"] != "COINFACTORY":
            if txn not in blockchain.fisrt_txn_block:
                return Response("Invalid txn!", status=400)

        for element in txn["outputs"]:
            if type(element) == dict:
                if element["recipient"] not in blockchain.utxo:
                    blockchain.utxo[element["recipient"]] = [ [element["amount"], block["index"], txn["hash"]] ]
                else:
                    blockchain.utxo[element["recipient"]].append([element["amount"], block["index"], txn["hash"]])

    blockchain.new_block(block)
    blockchain.save()
    if (blockchain.last_block["index"] + 1) % 5 == 0:
        blockchain.difficulty = Blockchain.difficulty_recalculation(blockchain.chain, blockchain.scaler, blockchain.difficulty, 5)

    if not blockchain.del_fisrt_txn_block():
        return Response("Something broke... Change node", status=500)
        ###############################

    nodes.send_block(block, node)

    return Response("OK", status=200)

@app.route('/get_blockchain', methods=['GET'])
def get_blockchain():
    return {"blockchain":blockchain.chain}

@app.route('/get_inp', methods=['GET'])
def get_inp():
    try:
        inputs = blockchain.utxo[request.args["address"]]
    except KeyError:
        inputs = []
    return {"utxo":inputs}

@app.route('/get_block', methods=['GET'])
def get_block():
    try:
        block = blockchain.chain[int(request.args["index"])]
    except KeyError:
        return Response("Invalid block index!", status=400)
    except:
        return Response("Invalid params!", status=400)
    return {"block":block}

@app.route('/get_txn_flow', methods=['GET'])
def get_txn_flow():
    try:
        return {"txn_blocks":blockchain.txn_blocks, "not_distributed_txns":blockchain.not_distributed_txns, "k":blockchain.k}
    except:
        return Response("Someting went wrong!", status=400)

@app.route('/get_txn_block', methods=['GET'])
def get_txn_block():
    try:
        return {"txn_block":blockchain.fisrt_txn_block, "target":Blockchain.gen_target(blockchain.difficulty)}
    except:
        return Response("Someting went wrong!", status=400)

@app.route('/get_txn', methods=['GET'])
def get_txn():
    try:
        return {"txn":blockchain.get_txn(int(request.args["block"]), request.args["txn"])}
    except:
        raise
        return Response("Invalid params!", status=400)

@app.route('/get_blockchain_length', methods=['GET'])
def get_blockchain_length():
    return {"length":len(blockchain.chain)}

@app.route('/new_node', methods=['POST'])
def new_node():
    data = request.get_json()
    try:
        nodes.new_node(data["uuid"], data["port"], request.remote_addr)
        return Response(blockchain.nodes.uuid, status=200)
    except:
        return Response("Invalid params!", status=400)

if __name__ == '__main__':
    if platform.system() == "Windows":
        os.system("cls")
    elif platform.system() == "Linux":
        os.system("clear")

    print(banner)
    Updater.update()

    ans = input(f" [ ~ ] Your external IP is {socket.gethostbyname(socket.gethostname())}. Is is correct (y/n)? >> ")
    if ans.lower() == "y":
        ip = socket.gethostbyname(socket.gethostname())
    else:
        ip = input(" [ ~ ] Input your IP: ")
    port = int(input(" [ ~ ] Select port: "))

    nodes = Nodes(port)
    blockchain = Blockchain(nodes)
    blockchain.sync_blockchain()

    print(" ")
    app.run(host=ip, port=port)
