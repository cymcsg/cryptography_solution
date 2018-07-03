import {Component} from '@angular/core';
import {TextEncoder} from 'text-encoding-shim';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  pub_a: any; // Public Key of A Side
  pub_pem_key_a: any; // pem of A side to pub_key
  pri_a: any; // Private Key of A Side
  pem_a: any; // Pem of A Side


  pub_b: any; // Public Key of B Side
  pub_pem_key_b: any; //  pem of B side to pub_key
  pri_b: any; // Private Key of B Side
  pem_b: any; // Pem of B Side


  generate_A() {
    const mythis = this;
    crypto.subtle.generateKey(
      {
        name: 'ECDH',
        modulusLength: 256,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        namedCurve: 'P-384'
      },
      false,
      ['deriveKey', 'deriveBits']
    ).then(function (keys) {
      mythis.pri_a = keys.privateKey;
      return window.crypto.subtle.exportKey('spki', keys.publicKey);
    }).then(function (keydata) {
      var pem = mythis.spkiToPEM(keydata);
      mythis.pem_a = pem;
      mythis.changepemAToPubAkey(pem);
      document.getElementById('key_a').innerHTML = pem;
    });
  }


  generate_B() {
    var _mythis = this;
    crypto.subtle.generateKey(
      {
        name: 'ECDH',
        modulusLength: 256,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        namedCurve: 'P-384'
      },
      false,
      ['deriveKey', 'deriveBits']
    ).then(function (keys) {
      _mythis.pri_b = keys.privateKey;
      // _mythis.publicKeyImport(keys.publicKey);
      return window.crypto.subtle.exportKey('spki', keys.publicKey);
    }).then(function (keydata) {
      var pem = _mythis.spkiToPEM(keydata);
      _mythis.pem_b = pem;
      _mythis.changepemBToPubAkey(pem);
      document.getElementById('key_b').innerHTML = pem;
    });
  }


  // B side: get share key
  share_key_A() {
    var _mythis = this;
    window.crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: _mythis.pub_pem_key_a // an ECDH public key from generateKey or importKey
      },
      _mythis.pri_b, // your ECDH private key from generateKey or importKey
      384 // the number of bits you want to derive
    )
      .then(function (bits) {
        var pem = _mythis.spkiToPEM(bits);
        document.getElementById('share_key_pubA_priB').innerHTML = pem;
      });
  }


  // A side: get share key
  share_key_B() {
    var _mythis = this;
    window.crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: _mythis.pub_pem_key_b // an ECDH public key from generateKey or importKey
      },
      _mythis.pri_a, // your ECDH private key from generateKey or importKey
      384 // the number of bits you want to derive
    )
      .then(function (bits) {
        var pem = _mythis.spkiToPEM(bits);
        document.getElementById('share_key_pubB_priA').innerHTML = pem;

      });
  }


  // transfer keydata to pem
  spkiToPEM(keydata) {
    var keydataS = this.arrayBufferToString(keydata);
    var keydataB64 = window.btoa(keydataS);
    var keydataB64Pem = this.formatAsPem(keydataB64);
    return keydataB64Pem;
  }

  arrayBufferToString(buffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return binary;
  }


  formatAsPem(str) {
    var finalString = '-----BEGIN PUBLIC KEY-----\n';
    while (str.length > 0) {
      finalString += str.substring(0, 64) + '\n';
      str = str.substring(64);
    }
    finalString = finalString + '-----END PUBLIC KEY-----';
    return finalString;
  }


  base64StringToArrayBuffer(base64) {
    var binary_string = atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
  }


  changepemAToPubAkey(pem) {
    var arr1 = pem.split('-----');
    var finalStr = arr1[2];
    var arrayB = this.base64StringToArrayBuffer(finalStr);
    var byteArray = new Uint8Array(arrayB);

    var _mythis = this;
    crypto.subtle.importKey('spki', byteArray, {
      name: 'ECDH',
      namedCurve: 'P-384'
    }, true, []).then(function (keydata) {
      _mythis.pub_pem_key_a = keydata;
    });

  }


  changepemBToPubAkey(pem) {
    var arr1 = pem.split('-----');
    var finalStr = arr1[2];
    var arrayB = this.base64StringToArrayBuffer(finalStr);
    var byteArray = new Uint8Array(arrayB);
    var _mythis = this;
    crypto.subtle.importKey('spki', byteArray, {
      name: 'ECDH',
      namedCurve: 'P-384'
    }, true, []).then(function (keydata) {
      _mythis.pub_pem_key_b = keydata;
    });
  }

  hex(buff) {
    return [].map.call(new Uint8Array(buff), b => ('00' + b.toString(16)).slice(-2)).join('');
  }

  aes_encry() {
    const data_str = 'hello aes';
    const byteArray = new TextEncoder().encode(data_str);
    const kNonalNonce = '540929e21c04a3a4bef16fe3';
    const typedArray = new Uint8Array(kNonalNonce.match(/[\da-f]{2}/gi).map(function (h) {
      return parseInt(h, 16);
    }));

    const kNonalNonce_buffer = typedArray.buffer;
    const sharekeyPemStr = 'YKVD42i3sY17MIfV8BERh0oM7Ti2AcDkLH+4gG/RVHaUKsD5EhOXs5ugTGKNXS3j';

    function hash(algo, str) {
      return crypto.subtle.digest(algo, new TextEncoder().encode(str));
    }

    hash('SHA-256', sharekeyPemStr).then(hashed => {
      window.crypto.subtle.importKey(
        'raw', // can be "jwk" or "raw"
        hashed,
        {   // this is the algorithm options
          name: 'AES-GCM',
        },
        true, // whether the key is extractable (i.e. can be used in exportKey)
        ['encrypt', 'decrypt'] // can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
      )
        .then(function (key) {
          window.crypto.subtle.encrypt(
            {
              name: 'AES-GCM',
              iv: kNonalNonce_buffer,
            },
            key, // from generateKey or importKey above
            byteArray // ArrayBuffer of data you want to encrypt
          ).then(function (encrypted) {
            function buf2hex(buffer) { // buffer is an ArrayBuffer
              return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
            }

            const hex = buf2hex(encrypted);
            document.getElementById('aes_encry').innerHTML = hex;

          });

        });
    });


  }


}
