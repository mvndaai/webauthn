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

    var obj = { strToBin, binToStr };

    if (typeof define === 'function' && define.amd)
        define('webauthn', obj);
    else if (typeof module !== 'undefined' && module.exports)
        module.exports = obj;
    else if (!global.webauthn)
        global.webauthn = obj;

})(this);