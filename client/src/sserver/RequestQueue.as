/**
 * Created by abrashkin on 15.10.2014.
 */
package sserver {
import flash.utils.setTimeout;

import sserver.api.IRequestQueue;
import sserver.api.ISServer;

/**
 * Данный класс реализован для того чтобы можно было осуществлять отправку запросов сразу после обмена ключами
 */

public class RequestQueue implements IRequestQueue{

    private var _queue          : Vector.<SSRequest>;
    private var _server         : ISServer;
    private var _requestTimeout : Number;
    private var _onComplete     : Function;

    public function RequestQueue( server: ISServer, requestTimeout: Number = 500 ) {
        _requestTimeout = requestTimeout;
        _queue    = new Vector.<SSRequest>();
        _server   = server;
    }

    public function get requestTimeout():Number {
        return _requestTimeout;
    }

    public function set requestTimeout(value:Number):void {
        _requestTimeout = value;
    }

    internal function add( request:SSRequest ):void {
        if( !request ) throw new Error("Request can't be null!");
        if( _server.isReady ){
            request.execute( _server );
        }else{
            _queue.push( request );
        }
    }

    /**
     * Запускает отправку запросов с интервалом requestTimeout
     */
    internal function execute( onComplete:Function ):void{
        _onComplete = onComplete;
        _executeNext();
    }

    private function _executeNext():void{
        if( !_queue.length ){
            if( _onComplete ) _onComplete.call( this );
            return;
        }
        var request : SSRequest = _queue.shift();
        request.execute( _server );
        setTimeout(_executeNext, _requestTimeout);
    }


}
}
