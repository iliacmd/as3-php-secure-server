package sserver {

import flash.events.EventDispatcher;

import sserver.api.IRequestQueue;
import sserver.api.ISServer;
import sserver.comps.crypt.Crypt;
import sserver.comps.crypt.api.ICrypt;
import sserver.comps.dh.DHKeysExchange;
import sserver.comps.dh.DHKeysExchangeEvent;

/*

    Клиентсвикй интерфейс для php сервера,
    с защитой на основе алгоритма Диффи-Хелмана и симметричного шифрования AES

*/

public class SServer extends EventDispatcher implements ISServer{

    private var _crypt          : ICrypt,
                _requestQueue    : RequestQueue,
                _isReady        : Boolean = false,
                _defaultURL     : String = "http://localhost/scripts/service/service.php"; // "https://flash.intellin.ru/crypto/service.php";//

    public function SServer( url:String ) {

        _defaultURL = url;
        _requestQueue = new RequestQueue( this );

    }

    public function start():void {
        var dhExchange : DHKeysExchange = new DHKeysExchange();
        dhExchange.addEventListener( DHKeysExchangeEvent.COMPLETE, handlerCompleteExchangeKeys );
        dhExchange.addEventListener( DHKeysExchangeEvent.ERROR, handlerErrorExchangeKeys );
        dhExchange.startExchange( _defaultURL );
    }

    public function setURL( url:String ):String {
        return _defaultURL = url;
    }

    public function send( req : SSRequest ):void{
        if( !req ) throw  new Error("Request can't be null!");
        _requestQueue.add( req );
    }

    private function handlerCompleteExchangeKeys(event:DHKeysExchangeEvent):void {
        //trace( "Shared Key:", event.sharedKey );
        _crypt = new Crypt( event.sharedKey, Crypt.AES256_CBC  );
        _isReady = true;
        _requestQueue.execute( function(){
            dispatchEvent( new SServerEvent(SServerEvent.READY) );
        });
    }

    private function handlerErrorExchangeKeys(event:DHKeysExchangeEvent):void {
        dispatchEvent( new SServerEvent(SServerEvent.ERROR_KEY_EXCHANGE) );
    }

    public function get crypt():ICrypt {
        return _crypt;
    }

    public function get defaultURL():String {
        return _defaultURL;
    }

    public function get requestQueue():IRequestQueue {
        return _requestQueue;
    }

    public function get isReady():Boolean {
        return _isReady;
    }


}
}
