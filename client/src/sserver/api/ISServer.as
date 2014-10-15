/**
 * Created by abrashkin on 15.10.2014.
 */
package sserver.api {
import flash.events.IEventDispatcher;

import sserver.*;
import sserver.comps.crypt.api.ICrypt;

public interface ISServer extends IEventDispatcher{
    function send(req:SSRequest):void
    function start():void;
    function get isReady():Boolean;
    function get crypt():ICrypt
    function get defaultURL():String
    function get requestQueue():IRequestQueue;
}

}
