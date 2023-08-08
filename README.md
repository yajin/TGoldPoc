# TGoldPoc

This repo contains the PoC of the [public transfer vulnerability in the Tether Gold contract](https://blocksecteam.medium.com/public-transfer-vulnerability-of-the-tether-gold-smart-contract-662694607d35).


To use this PoC, sign up in [Phalcon Fork](https://phalcon.xyz/fork). Then add the access key to the PoC.



This PoC requires the web3.py, please install it first to use the PoC.

```
>>python tgold.py
--------------------start ----------
[*] Insufficent fund in "0x189e7947a9D9210eEC3A41dCf5f536bb1D7726F5". Get some Ether from vitalik.
[*] Insufficent fund in "0x14C4fffd8748CF0E23Af945a11eeaBC3416dD4c1". Get some Ether from vitalik.
[*] 0xAC3B242E2E561da9F4cE34746E67d004E6341FA0 Submit a transaction in the multisig wallet to transferOwnership to 0x189e7947a9D9210eEC3A41dCf5f536bb1D7726F5.
proposal_id: 2207
[*] Confirmed the transaction by 0xEe5207d3c88562fc814496Af0845B34CFD4afc8c.
[*] Confirmed the transaction by 0x61D5a4d5Bd270e59E9320243e574288e2a199fED.
[*] The pool owner is "0x189e7947a9D9210eEC3A41dCf5f536bb1D7726F5"
[*] Add a new owner "0x189e7947a9D9210eEC3A41dCf5f536bb1D7726F5" to TGold contract
[*] Before the attack - balance: 0
[*] Lunch the attack
[*] After the attack - balance: 2000000
[*] Owned!
```

If you have any question please contact us contact@blocksec.com.



