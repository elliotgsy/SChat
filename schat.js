
$(function() {

  
    const NodeRSA = require("node-rsa");
    const Crypto = require('crypto');



    var localKey = new NodeRSA({b: 512});
    var remoteKey = new NodeRSA(null, 'pkcs8-public-pem');
    
    var remoteAddress = "127.0.0.1";
    var localPort = 8087;
    var remotePort = localPort;

    const dgram = require('dgram');
    var server = dgram.createSocket('udp4');

    $("#b-local-keypair").click(function() {
        let bitCount = $("#local-bitcount").val(); 
        if(bitCount % 8 == 0) {
            if(bitCount >= 8 && bitCount <= 16384) {       
                generateNewKeypair(bitCount);
                outputKeys();
            } else {
                $("#local-keypair").val("The bitcount must be between 8-32,768");
            }
        } else {
            $("#local-keypair").val("The bitcount must be a multiple of 8 (512, 8, 2048, 1024)");
        }
    });

    $("#b-remote-address").click(function() {
        let ra = $("#remote-address").val();
        remoteAddress = ra;
        localPort = $("#local-port").val();
        remotePort = $("#remote-port").val();
        setupServer();
        console.log("Remote Address set to " + ra);
    });

    $("#b-remote-public-key").click(function() {
        let rpk = $("#remote-public-key").val();
        loadKey(rpk);
        console.log("Remote Public Key set to " + rpk);
    });

    $("#message-input").keypress(function(e) {
        let msg =  $("#message-input").val();
        if(e.which == 13) {
            $("#message-input").val('');
            sendMessage(msg);
            console.log("Attempting to send message " + msg);
        }
    });

    loadKey = function(key) {
        try {
            remoteKey.importKey(key, "public");
        } catch(err) {
            $("#remote-public-key").val("Invalid public key (PKCS8-PUBLIC-PEM)");
        }
    }

    generateNewKeypair = function(bitCount) {
        localKey = new NodeRSA({b: bitCount});
        localKey.setOptions({encryptionScheme: 'pkcs1_oaep'});
    }

    outputKeys = function() {
        const publicKey = localKey.exportKey("public"); 
        const privateKey = localKey.exportKey("private"); 
        $("#local-public").val(publicKey);
        $("#local-private").val(privateKey);
    }

    sendMessage = function(msg) {
        if(checkNullOrWhiteSpace(msg)) { return; }
        $("#message-output").append("Local -> " + remoteAddress + ": " +  msg + "\n");
        const eMsg = remoteKey.encrypt(msg, 'base64');
        console.log(eMsg);
        const message = Buffer.from(eMsg);
        server.send(message, 0, message.length, remotePort, remoteAddress);
    }

    receiveMessage = function(msg, rinfo) {
        console.log("." + msg + ".");
        var ueMsg = "UNDEFINED";
        try {
            ueMsg = localKey.decrypt(new String(msg), 'utf8');
        } catch(err) {
            $("#message-output").append(rinfo.address + ":" + rinfo.port + " has sent you an invalid message. \n");
            return;
        }
        $("#message-output").append("Local <- " + remoteAddress + ": " +  ueMsg + "\n");
    }

    checkNullOrWhiteSpace = function(str) {
        return (/^\s*$/.test(str) || !str || str.length === 0)
    }

    setupServer = function() {

        try {
            server.close();
        } catch (err) {
            
        }
        server = dgram.createSocket("udp4");

        server.on('error', (err) => {
            console.log(`server error:\n${err.stack}`);
            server.close();
        });

        server.on('message', (msg, rinfo) => {
            console.log(`server got: ${msg} from ${rinfo.address}:${rinfo.port}`);
            receiveMessage(msg, rinfo);
        });

        server.on('listening', () => {
            const address = server.address();
            console.log(`server listening ${address.address}:${address.port}`);
        });

        server.bind(localPort);
    }

    setupServer();
    
   // const text = 'Hello RSA!';
   // const encrypted = key.encrypt(text, 'base64');
   // console.log('encrypted: ', encrypted);
   // const decrypted = key.decrypt(encrypted, 'utf8');
   // console.log('decrypted: ', decrypted);
});