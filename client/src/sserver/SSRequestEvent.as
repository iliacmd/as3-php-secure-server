/**
 * Created by abrashkin on 15.10.2014.
 */
package sserver {
import flash.events.Event;

public class SSRequestEvent extends Event {

    public static const ERROR       : String = "error_event",
                        COMPLETE    : String = "complete_event";

    public function SSRequestEvent( type:String ) {
        super(type)
    }
}
}
