<?php

require_once "GibberishAES.php";

class Crypt
{
    var $key    = NULL;
    var $iv     = NULL;
    var $size   = NULL;
    var $iv_size= NULL;

    function Crypt()
    {
        $this->init();
    }

    function isKeyExists(){
        if( $this->key ){
            return true;
        }else{
            return false;
        }
    }

    function init( $key = "", $size = 128)
    {
        $this->size = $size;
        $this->key = ($key != "") ? $key : "";
        GibberishAES::size( $this->size );
    }

    function encrypt($data)
    {
        return GibberishAES::enc($data, $this->key);
    }

    function decrypt($data)
    {
        return GibberishAES::dec($data, $this->key);
    }

}
