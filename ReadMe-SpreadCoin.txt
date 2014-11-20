******************************
*      Starting miner        *
******************************

IMPORTANT: you must you use wallet version 0.9.14.4 or newer.

1. You need to add the following 4 lines to your spreadcoin.conf
(C:\Users\<user>\AppData\Roaming\SpreadCoin\spreadcoin.conf on Windows 7, create it if it doesn't exist):

server=1
rpcallowip=127.0.0.1
rpcuser=user
rpcpassword=pass

You can use different username and password. These settings allow connections only from
the same computer so strength of the password isn't very important.

If your wallet is password-ptotected than you will need either to unlock your wallet or explicitly specify mining address (see below).

2. Restart the wallet after modifying spreadcoin.conf.

3. Now you can launch miner using the following command:

sgminer -o "http://127.0.0.1:41677" -u user -p pass --thread-concurrency 8192 --lookup-gap 2 --worksize 64 -g 2 -I 11

There is start.bat to do this, just edit it and enter your username and password that you specified in spreadcoin.conf.

For me it was also necessary to add
--gpu-platform 1
to the argument list to make it work. You may or may not need this.

******************************
*    Mining parameters       *
******************************
These paramterers (--thread-concurrency 8192 --lookup-gap 2 --worksize 64 -g 2 -I 11) are probably not very good but
I can get around 550 kh/s on AMD R9 280X. If you will try to experiment with these parameter you will probably be able
to increase your hashrate.

******************************
* Mining to specific address *
******************************
Also you can mine to a specific address. To do so:

1. Use existing or better generate a new address.
2. Open debug console (Tools -> Debug Console) and enter:

    dumpprivkey SYourSpreadCoinAddress

3. You will get your private key. Open spreadcoin.conf and add the following line:

    miningprivkey=YourPrivateKey

4. Restart your wallet if it was running. In the Mining tab you will now see notification that all mined coins will go to this address.