/**
 * Created by abrashkin on 15.10.2014.
 */
package sserver {
import flash.events.Event;
import flash.events.EventDispatcher;
import flash.events.IOErrorEvent;
import flash.net.URLLoader;
import flash.net.URLRequest;
import flash.net.URLRequestMethod;
import flash.net.URLVariables;

import sserver.api.ISServer;

public class SSRequest extends EventDispatcher{

    private var _onComplete : Function;
    private var _onError    : Function;
    private var _method     : String;
    private var _args       : Array;
    private var _server     : ISServer;

    public function SSRequest(  method: String, args: Array, onComplete:Function = null, onError: Function = null ) {
        _method     = method;
        _args       = args;
        _onComplete = onComplete;
        _onError    = onError;
    }

    internal function execute( server: ISServer ):void {

        _server = server;

        if( !_method )
            throw new Error("Method name is can't be null!");

        var request : URLRequest = new URLRequest( _server.defaultURL );
        request.method  = URLRequestMethod.POST;
        request.data    = new URLVariables();
        request.data.message = _server.crypt.encrypt( JSON.stringify({data: {method: _method, args: _args}}) );

        var loader : URLLoader = new URLLoader();
        loader.addEventListener( Event.COMPLETE, handlerCompleteRequest );
        loader.addEventListener( IOErrorEvent.IO_ERROR, handlerErrorRequest );
        loader.load( request );

    }

    protected function handlerErrorRequest(event:IOErrorEvent):void {
        if( _onError )_onError.call( this, event.text );
        event.target.removeEventListener( Event.COMPLETE, handlerCompleteRequest );
        event.target.removeEventListener( IOErrorEvent.IO_ERROR, handlerErrorRequest );
        dispatchEvent( new SSRequestEvent(SSRequestEvent.COMPLETE) );
    }

    protected function handlerCompleteRequest( event:Event ):void {
        var response : String = _server.crypt.decrypt(event.target.data);
        if( _onComplete )_onComplete.call( this,  response );
        //trace( "Sever - Response:", event.target.data );
        //trace( "Sever - Response:", _crypt.decrypt(event.target.data)  );
        event.target.removeEventListener( Event.COMPLETE, handlerCompleteRequest );
        event.target.removeEventListener( IOErrorEvent.IO_ERROR, handlerErrorRequest );
        dispatchEvent( new SSRequestEvent(SSRequestEvent.ERROR) );
    }

}
}
