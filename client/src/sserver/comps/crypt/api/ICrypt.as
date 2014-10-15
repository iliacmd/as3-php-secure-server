/**
 * Created by abrashkin on 15.10.2014.
 */
package sserver.comps.crypt.api {
public interface ICrypt {
    function encrypt(txt:String = ''):String
    function decrypt(txt:String = ''):String
}
}
