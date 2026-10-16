# Reach Kart

![](logo.png)

## Sherlock scenario

ReachKart is an e-commerce website running on Ehtereum blockchain technology, to support rapid development without disrupting the live environment, the company implemented a "production mirror" strategy, creating an exact replica of the production environment for development and testing purposes. The mirror includes replicated databases, services and blockchain nodes, but it appears that customer data has not been anonymized. Customer support is now receiving emails from sellers complaining that their wallets are missing ether. You have to investigate and understand if and how an intrusion has occurred.

## Given artifacts

A packet capture file and the server's access log

## Foundational knowledge: Ethereum and Hardhat

Only a few blockchain concepts are needed for this investigation:

- **Ethereum** is a blockchain that records transactions in blocks. **Ether (ETH)** is its native currency, and **Wei** is its smallest unit (`1 ETH = 10^18 Wei`). Amounts in Ethereum JSON-RPC responses are frequently represented as hexadecimal Wei values.
- A **wallet address** identifies an account, but it is public information. To spend ETH from a normal externally owned account, a transaction must be authorized with the corresponding **private key** (or another mechanism with equivalent signing authority).
- A **transaction** includes a sender (`from`), potentially a recipient (`to`), an amount (`value`), and a nonce. A transaction can transfer ETH, interact with a smart contract, or deploy one; it is not necessarily a payment. Its **transaction hash** identifies that transaction.
- **Gas** measures execution work and determines transaction fees. `eth_estimateGas` only estimates the execution cost of a *proposed* transaction; it does not submit or confirm one.
- **Hardhat** is an Ethereum development framework with a local Ethereum-compatible node. Applications communicate with nodes using **JSON-RPC**, commonly through HTTP on port `8545`. In this PCAP, these readable RPC calls are useful forensic artifacts.

The particularly useful RPC methods are `eth_sendRawTransaction` (submit a signed transaction), `eth_sendTransaction` (ask a node to submit a transaction using an account it can sign for), `eth_getTransactionByHash` (retrieve transaction details), `eth_getTransactionReceipt` (retrieve the execution outcome and block), and `eth_getBalance` (read an account's balance). A successful `eth_sendRawTransaction` response only shows that the node accepted the submission; a receipt with `status: 0x1` provides stronger evidence that the transaction executed successfully. A missing receipt *in the capture* does not prove that it failed.

## Questions

### 1. What was the vulnerable endpoint that allowed the attacker to leak files?

This question can either be tackled by looking at the pcap or the access log. Here I use the pcap for a better grasp of the scenario. The attacker signs up for an accound then use it to log in. After browsing some page, he finds the vulnerable endpoint, which exposes LFI:

![](1.png)

**Answer: /user/getOrderBill**

### 2. When was the first successful exploitation of the vulnerable endpoint by the attacker (time in UTC)?

The attempt for `/etc/passwd` is their first file they try. After some fail queries, they eventually get a 200 OK response. Change the time display format to get UTC timestamp:

**Answer: 2025-03-01 04:09:22**

### 3. Which version of Express is currently being used on the server?

After that, they aims for another file, `package.json`, which is a config file holding a lot of metadata about the web app, frequently seen in `Node.js` web app. From the server's response for that file, we can see in the `dependencies` key:

![](2.png)

**Answer: 4.21.2**

### 4. Which Ethereum compatible development smart contract network is running on the server? (Format: name@version)

From that image, we can also see another dependency involving Etherum crypto-currency: Hardhat.

Hardhat is a development environment and framework for building, testing, and
deploying Ethereum-compatible smart contracts. It provides a local Ethereum network,
advanced debugging tools, and automation features that simplify the smart contract
development process. If Hardhat is used with real wallets or private keys in an
unsecured environment, such as exposing them in code, committing them to version
control, or using a public RPC endpoint, it can be exploited by attackers to gain access
to those wallets and steal Ether.

**Answer: hardhat@2.22.18**

### 5. What is the signing key used by the server to sign JSON Web Tokens (JWT)?

After observing the package configuration file, they continue to download some other javascript files like `rk-logging.js` and `rk-server.js`, source code of the server. I export them for further inspection, upon reading the logging js, I see an .env explicitly saying it is used to sign JWT:

![](3.png)

**Answer: SuperSecretPassword**

### 6. The attacker was able to generate a JWT from the signing key and log in to the admin panel. What is the JWT value?

From `rk-server.js`, we can see some endpoints can only be accessed as an admin:

![](4.png)

Not long after they get the javascript source, they successfully access the admin panel with this particular JWT:

![](5.png)

**Answer: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiRGFydGggVmFkZXIiLCJlbWFpbCI6ImRhcnRodmFkZXJAZW1waXJlLmNvbSIsImFjY291bnRfdHlwZSI6ImFkbWluIiwiaWF0IjoxNzQwODAyNzM0LCJleHAiOjE3NDA4ODkxMzR9.RBmMEC7IYmkzz1LsT-kP_JkLCUb7-hsJKX4IdjE91TE**

### 7. Decode the token and find the email used by the attacker to log in to the admin panel.

Decode the JWT using cyberchef, this turns out to be the email attacker used to sign up for an account from the beginning:

![](6.png)

**Answer: darthvader@empire.com**

### 8. The admin panel uses WebSocket to send and receive terminal input. What port is being used?

Can be seen from the server's source code:

![](7.png)

Double-check by filtering for web socket traffic in the pcap, it actually runs on port 8888

**Answer: 8888**

### 9. The attacker then was able to retrieve a sensitive file. When did the attacker get the file (UTC)?

Follow the websocket stream, we can see the attacker seem to pay attention to this file:

![](8.png)

Then a HTTP request is sent to get it:

![](9.png)

**Answer: 2025-03-01 04:22:01**

### 10. What is the SHA-256 hash of the file that the attacker downloaded ?

Export it from wireshark, and take the hash

**Answer: fabe3234bb709ee5e5c5c2789c891a9a49368ffa520b23d60f6be2f2ca81bac6**

### 11. How many sellers are there in the e-commerce website?

Open the database file in DB Browser:

![](10.png)

**Answer: 8**

### 12. The attacker started sending Ether from all identified sellers' wallets. What is the hash of the first transaction?

After holding the database, we can see subsequence RPC made by the attacker, he first inspect balance of the user with this wallet ID:

![](11.png)

After checking estimated gas and some other things, he calls `sendRawTransaction` to send ETH to his wallet:

![](12.png)

Although the response to this call contains the transaction's hash, it's not confirmed, this transaction is just submitted, not included in a block and executed yet. Therefore, we will find the get receipt call to confirm:

![](13.png)

**Answer: 0x7b7ded2d51f0dcb1bf3fc5cc9598b81a7a622aac15d3841d377c548986e0a7c3**

### 13. What was the total amount of Ether stolen by the attacker? (1 Eth = 10^18 wei)

My approach is to follow the call to `estimateGas`, note that this works in this case, but it's not guaranteed, as it is just the proposal, we must inspect the stream to determine whether the transaction is confirmed or not. But it's quite burdensome, so I will talk about the working shorcut here, we also need CLI Kung-fu to efficiently filter the desired value.

First notice the pattern involving value in the `estimateGas` call:

![](14.png)

We will use tshark, filter for TCP on port 8545, frame containing the RPC and the WID of one of the seller, the grep for the line in above screenshot, cut by delimeter `:` then truncate the trailing `]`

```bash
amounts=$(tshark -r network-traffic.pcap -Y "tcp.port == 8545 && http.request && frame contains \"eth_estimateGas\" && (frame contains \"0x509625aaa1067a52258414db03a0a50b72714bf2\" || frame contains \"0xa7cc4003ec3a8117db86df2be678647607c39509\" || frame contains \"0x6644b3ea41b62332c226868f15197451800fab02\" || frame contains \"0xfa0ce871b4b4ab8b14fb86c22598c05cdf163beb\" || frame contains \"0x7a1f3f14c42c23cee151f47ba03dde150248f27f\" || frame contains \"0x38da134bb2258681f408a8f8c43dec0a1bc8451e\" || frame contains \"0x1fab914fa65d631ba3d79eaddc10cab080e476b0\" || frame contains \"0x0af037e4d0b3a05489d6416b8ed0d847c6a213ca\")" -V | grep "value: value:" | cut -d ":" -f 3 | tr -d "]")
```

Note that if you use single quote, there is no need to escape the `"` character

![](15.png)

Convert them to decimal, sum them and divide by 10^18 as guided

**Answer: 24.4**

### 14. What is the block number of the last transaction in which Ether was stolen? (Decimal)

Search for the `getTransactionReceipt` RPC, and find for the last entry:

![](16.png)

**Answer: 18**

### 15. After the attacker stole the Ether, what was the balance in their wallet? (Ignore the trailing zeros)

Right after the last steal, the attacker call `getBalance` for his account:

![](17.png)

**Answer: 24.40023**

## Afterthought

The compromised `reachkart.db` exposes seller wallet addresses and connects the victims to the subsequent blockchain activity, but **an address alone is not enough to steal ETH**. It is public, like an account identifier, not a private signing key. Spending funds requires control of the seller's private key or access to another authorized signing mechanism (for example, a node or service holding unlocked accounts). The visible transactions establish that transfers occurred, but the database leak by itself does **not** establish how the attacker gained signing authority. That step remains an evidentiary gap in the scenario.

One other detail is worth preserving: traffic before the observed LFI exploit includes a successful **0.00023 ETH** transfer into the address later used as the theft destination. This helps explain why the final balance (`24.40023 ETH`) exceeds the amount stolen from sellers (`24.4 ETH`). We should not automatically label every earlier transaction as malicious, or every gas-estimation request as a completed transfer. For a rigorous investigation, correlate transaction hashes, sender/recipient addresses, values, and successful receipts rather than relying on timing or estimates alone.
