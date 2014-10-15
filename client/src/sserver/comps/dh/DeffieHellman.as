/**
 * Created by abrashkin on 10.10.2014.
 */
package sserver.comps.dh {
import com.hurlant.math.BigInteger;

public class DeffieHellman {

    private var   _prime        : BigInteger,
                  _gen          : BigInteger,
                  _privateKey   : BigInteger,
                  _compositeKey : BigInteger;

    public function DeffieHellman( prime:String, gen: String, privateKey: String = "" ){

        _prime      = new BigInteger( prime, 10);
        _gen        = new BigInteger( gen, 10);

        if( privateKey )
            _privateKey = new BigInteger(privateKey, 10);
        else
            _privateKey = new BigInteger( _randString( 150 ), 10 );

    }

    public function getPrivateKey():BigInteger{
        return _privateKey;
    }

    public function setCompositKey( key: String ):BigInteger{
        _compositeKey = new BigInteger( key, 10 );
        return _compositeKey;
    }


    public function getPublicKey():BigInteger{
        return _gen.modPow(_privateKey, _prime);
    }

    public function getSharedKey():BigInteger{
        if( !_compositeKey.bitLength() ) throw new Error("Composite key is null!");
        return _compositeKey.modPow(_privateKey, _prime);
    }

    public function get prime():BigInteger {
        return _prime;
    }

    private function _randString( len : int ):String {
        var randomString   : String = "";
        var characters     : String = '0123456789';
        for ( var i:int = 0; i < len; i++) {
            randomString += characters.charAt( Math.random()*(characters.length-1) );
        }
        return randomString;
    }


}
}
