package sserver {
import flash.display.Sprite;

import sserver.SSRequest;
import sserver.SServer;
import sserver.SServerEvent;
import sserver.api.ISServer;

public class SServerTest extends Sprite {

    private var _server : ISServer;

    public function SServerTest() {
    }

    public function run():void {

        _server= new SServer( "http://localhost/scripts/service/service.php" ); //"https://flash.intellin.ru/crypto/service.php";//
        _server.requestQueue.requestTimeout = 100;
        _server.addEventListener( SServerEvent.READY, handlerReady );
        _server.start();

        _server.send( new SSRequestCall("hello", ["Alex"], handlerHello, handlerHelloError ) );
        _server.send( new SSRequestCall("hello", ["Max"], handlerHello, handlerHelloError ) );
        _server.send( new SSRequestCall("hello", ["Jack"], handlerHello, handlerHelloError ) );

    }

    private function handlerReady( event:SServerEvent ):void {
        _server.send( new SSRequestCall("hello", ["Ilya"], handlerHello, handlerHelloError ) );
    }

    private function handlerHelloError( data:Object ):void {
        trace( data );
    }

    private function handlerHello( data:Object ):void {
        trace( data );
    }


}
}
