/**
 * Created by abrashkin on 15.10.2014.
 */
package sserver {
public class SSRequestCall extends SSRequest{

    public function SSRequestCall(  method: String, args: Array, onComplete:Function = null, onError: Function = null ) {
        super( JSON.stringify({data: {method: method, args: args}}), onComplete, onError )
        _onComplete = onComplete;
        _onError    = onError;
    }

}
}
