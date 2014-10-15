/**
 * Created by abrashkin on 15.10.2014.
 */
package sserver.comps.dh.api {
public interface IDHKeysExhange {
    function startExchange( server: String, privateKey : String = "" ):void;
}

}
