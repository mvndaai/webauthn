(function(global, undefined) {
    'use strict';

    function strToBin(str) {
        return Uint8Array.from(
            atob(str),
            function(c){ return c.charCodeAt(0); }
        );
    }

    function binToStr(bin){
        return btoa(new Uint8Array(bin).
            reduce(
                function(s, byte){ return s + String.fromCharCode(byte); }
                , ''
            )
        );
    }

    function buildPublicKey(builder){
        // builder.toArrayBuffer.map(function(b) {
        //     b.reduce(
        //         function(p){}
        //     )
        // });

        // let a = { b : {c : {d : 'e'}}}
        // ['b', 'c', 'd'].reduce((b,c) => {console.log(b,c); return b[c]}, a)
        return { publicKey: builder.publicKey };
    }

    var obj = { strToBin, binToStr, buildPublicKey };

    if (typeof define === 'function' && define.amd)
        define('webauthn', obj);
    else if (typeof module !== 'undefined' && module.exports)
        module.exports = obj;
    else if (!global.webauthn)
        global.webauthn = obj;

})(this);