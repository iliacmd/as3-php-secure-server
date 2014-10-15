/**
 * Created by abrashkin on 10.10.2014.
 */
package sserver.comps.dh {
import com.hurlant.math.BigInteger;

import flash.events.Event;
import flash.events.EventDispatcher;
import flash.net.URLLoader;
import flash.net.URLRequest;
import flash.net.URLRequestMethod;
import flash.net.URLVariables;

import sserver.comps.dh.api.IDHKeysExhange;

public class DHKeysExchange extends EventDispatcher implements IDHKeysExhange{

    private var _dh         : DeffieHellman,
                _server     : String,
                _privateKey : BigInteger;

    public function DHKeysExchange() {
    }

    public function startExchange( server: String, privateKey : String = "" ):void{
        _server     = server;
        _privateKey = (privateKey) ? new BigInteger( privateKey, 10 ) : new BigInteger( randString( 100 ), 10);
        sendRequestInvite();
    }

    private function sendRequestInvite():void {

        var loader : URLLoader = new URLLoader();
        loader.addEventListener( Event.COMPLETE, handlerCompleteGetKey );

        var request : URLRequest = new URLRequest( _server );
        request.method = URLRequestMethod.POST;
        request.data = new URLVariables();
        request.data.action = 1;

        loader.load( request );

    }


    private function handlerCompleteGetKey(event:Event):void {

        trace( this, "Server - Response: ", event.target.data );
        var response : Object = JSON.parse(event.target.data);

        if( !response &&
                !response.g &&
                !response.p &&
                !response.key ){
            trace( this, "invalid arguments ");
            return;
        }

        if( response.p.length < 2 ){
            trace( this, "invalid module");
            return;
        }

        var prime           : String = response.p;
        var gen             : String = response.g;
        var privateKey      : String = _privateKey.toRadix(10);
        var serverComposite : String = response.key;

        _dh = new DeffieHellman( prime, gen, privateKey );
        _dh.setCompositKey( serverComposite );

        trace( this, "Client - Composite Key: ",    _dh.getPublicKey().toRadix(10) );
        trace( this, "Client - Private Key: ",      _dh.getPrivateKey().toRadix(10) );
        trace( this, "Client - Shared Secret Key: ",_dh.getSharedKey().toRadix(10) );
        trace( this, "Server - Composite Key: ",  serverComposite );

        var request : URLRequest = new URLRequest( _server );
        request.method      = URLRequestMethod.POST;
        request.data        = new URLVariables();
        request.data.action = 2;
        request.data.key    = _dh.getPublicKey().toRadix(10);

        var loader : URLLoader = new URLLoader();
        loader.addEventListener( Event.COMPLETE, handlerCompleteSendKey );
        loader.load( request );

    }

    private function handlerCompleteSendKey(event:Event):void {

        trace( this, "Server - Response: ", event.target.data);

        var response : Object = JSON.parse(event.target.data);
        if( !response.error ){
            dispatchEvent( new DHKeysExchangeEvent(DHKeysExchangeEvent.COMPLETE,  _dh.getSharedKey().toRadix(10)) );
        }else{
            dispatchEvent( new DHKeysExchangeEvent(DHKeysExchangeEvent.ERROR, response.error ) );
        }

    }

    private function randString( len: int ):String {
        var randomString : String = "";
        while( randomString.length < len ){
          randomString += String( Math.random()*9 );
        }
        return randomString;
    }




}
}
