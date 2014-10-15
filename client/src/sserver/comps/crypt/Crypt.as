package sserver.comps.crypt
{
import sserver.comps.aes.AESCrypter;
import sserver.comps.crypt.api.ICrypt;

public class Crypt implements ICrypt
{
    private var _size   : int;
    private var _key    : String;

    public static const AES196_CBC : int = 196,
                        AES128_CBC : int = 128,
                        AES256_CBC : int = 256;

    public function Crypt( key:String, size:int = AES128_CBC  )
    {
        _key = key;
        _size = size;
        AESCrypter.size( size );
    }

    public function encrypt(txt:String = ''):String
    {
        return AESCrypter.enc(txt, _key);
    }
    public function decrypt(txt:String = ''):String
    {
        return AESCrypter.dec(txt, _key);
    }

}

}