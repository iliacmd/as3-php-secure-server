/**
 * Created by abrashkin on 10.10.2014.
 */
package sserver.comps.dh {
import flash.events.Event;

public class DHKeysExchangeEvent extends Event {

    public static const COMPLETE    : String = "complete_exchange_keys_event";
    public static const ERROR       : String = "error_exchange_keys_event";

    private var _sharedKey : String;

    public function DHKeysExchangeEvent(type:String, sharedKey: String ) {
        super(type, bubbles, cancelable);
        _sharedKey = sharedKey;
    }

    public function get sharedKey():String {
        return _sharedKey;
    }
}
}
