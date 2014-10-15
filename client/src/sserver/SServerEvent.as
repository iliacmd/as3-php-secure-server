/**
 * Created by abrashkin on 15.10.2014.
 */
package sserver {
import flash.events.Event;

public class SServerEvent extends Event {

    public static const READY : String = "server_ready_event";
    public static const ERROR_KEY_EXCHANGE : String = "error_key_exchange_event";

    private var _data:Object;

    public function SServerEvent(type:String, data: Object = null ) {
        super(type, bubbles, cancelable);
        _data = data;
    }

    public function get data():Object {
        return _data;
    }
}
}
