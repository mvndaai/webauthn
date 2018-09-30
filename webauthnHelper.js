(function(global, undefined) {
    'use strict';

    function strToBin(str) {
        return Uint8Array.from(
            atob(str),
            function(c){ return c.charCodeAt(0); }
        );
    }

    function binToStr(bin){
        return btoa(new Uint8Array(bin).reduce(
                function(s, byte){ return s + String.fromCharCode(byte); }
                , ''
        ));
    }

    function parseClientDataJSON(clientDataJSON) {
        return JSON.parse(atob(binToStr(r.response.clientDataJSON)));
    }

    // See CBOR.io or https://github.com/paroga/cbor-jsa
    function parseAttestationObject(attestationObject) {
        return CBOR.decode(attestationObject);
    }

    function unwrapPublicKeyCredential(cred) {
        let r = {response: {}};
        if ('id' in cred) r.id = cred.id
        if ('type' in cred) r.type = cred.type;
        if ('rawId' in cred) r.rawId = binToStr(cred.rawId);
        if ('response' in cred) {
            // Used in registration
            if ('clientDataJSON' in cred.response)
                r.response.clientDataJSON = binToStr(cred.response.clientDataJSON);
            if ('attestationObject' in cred.response)
                r.response.attestationObject = binToStr(cred.response.attestationObject);

            // Used in authentication
            if ('authenticatorData' in cred.response)
                r.response.authenticatorData = binToStr(cred.response.authenticatorData);
            if ('signature' in cred.response)
                r.response.signature = binToStr(cred.response.signature);
            if ('userHandle' in cred.response)
                r.response.userHandle = binToStr(cred.response.userHandle);
        }
        return r;
    }

    var obj = { strToBin, binToStr, parseClientDataJSON, parseAttestationObject, unwrapPublicKeyCredential };

    if (typeof define === 'function' && define.amd) define('webauthnHelper', obj);
    else if (typeof module !== 'undefined' && module.exports) module.exports = obj;
    else if (!global.webauthnHelper) global.webauthnHelper = obj;
})(this);