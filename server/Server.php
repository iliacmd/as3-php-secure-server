<?php

error_reporting(E_ALL);
ini_set('display_errors', 0);

require_once "Auth/OpenID/DiffieHellman.php";
require_once "api/API.php";
require_once "Crypt.php";
require_once 'Auth/OpenID/CryptUtil.php';

session_start();

$service = new Service();
$service->handleExchangeKeys();
$service->handleMessage();


class Service{

    private $dh;
    private $prime;
    private $gen;
    private $private;
    private $crypt;

    public function Service(){

        $this->crypt  = new Crypt();
        $this->prime    = $this->genRandomBigInt( 50 );
        $this->gen      = rand(1, 16);
        $this->private  = $this->genRandomBigInt( 50 );

        if( isset($_SESSION['p']) ){
            $this->prime = $_SESSION['p'];
        }else{
            $_SESSION['p'] = $this->prime;
        }

        if( isset($_SESSION['g']) ){
            $this->gen = $_SESSION['g'];
        }else{
            $_SESSION['g'] = $this->gen;
        }

        if( isset($_SESSION['pv']) ){
            $this->private = $_SESSION['pv'];
        }else{
            $_SESSION['pv'] = $this->private;
        }

        $this->dh = new Auth_OpenID_DiffieHellman( $this->prime, $this->gen, $this->private );

        if( isset($_SESSION[ 'client_composite' ]) ){
            $this->crypt->init( $this->dh->getSharedSecret( $_SESSION[ 'client_composite' ] ), 256 );
        }

    }

    public function genRandomBigInt($length = 15) {
        $characters = '0123456789';
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, strlen($characters) - 1)];
        }
        return $randomString;
    }

    public function decryptMsg( $message ){
        return $this->crypt->decrypt( $message );
    }

    public function encryptMsg( $message ){
        return $this->crypt->encrypt( $message );
    }

    public function handleExchangeKeys(){

        $action         = isset($_POST["action"])   ? $_POST["action"]  : 0;
        $composite_key  = isset($_POST["key"])      ? $_POST["key"]     : "";

        if( !isset($action) || empty($action) ) return;

        switch( $action ){
            case 1: // Приглашение к обмену ключами, отправляем клиенту свой композитный ключ
                $accept      = new AcceptInvite();
                $accept->p   = $this->prime;
                $accept->g   = $this->gen;
                $accept->key = $this->dh->getPublicKey();
                echo json_encode( $accept );
            break;
            case 2: // Получение композитного ключа от клиента и завершение обмена
                $_SESSION[ 'client_composite' ] = $composite_key;
                $this->crypt->init( $this->dh->getSharedSecret( $composite_key ) );
                if( $this->crypt->isKeyExists() ){
                    $message = new Message( "success", null );
                }else{
                    $message = new Message( null, "Can't get secret key!" );
                }
                echo json_encode( $message );
            break;
            default:
                $message = new Message( null, "Unknown step!" );
                echo json_encode( $message );
            break;
        }

    }

    public  function handleMessage(){

        $message       = ( isset($_POST["message"]) ) ? $_POST["message"] : "";
        $response      = new Message();

        if( !empty( $message ) ){

            if( $this->crypt->isKeyExists() ) {

                $request = $this->decryptMsg( $message );

                if( $message ){


                           $request = json_decode( $request );

                            if( $request && $request->data  )
                                $response->data =  FactoryAPI::callMethod( $request->data->method, $request->data->args );
                            else
                                $response->error = "Unknown method - ".$request->data->method;

                }else{
                    $response->error = "Can't json decode message" . $message;
                }

                echo $this->encryptMsg( json_encode($response) );

            }else{
                echo "ERROR: Can't accept message, because you not auth";
            }


        }


    }


}


class Message{

    public $data;
    public $error;

    public function Message( $data = null, $error = null){
        $this->data     = $data;
        $this->error    = $error;
    }
}


class AcceptInvite{

    public $p;
    public $g;
    public $key;
    public $status;

}

class EndExchange{
    public $status;
}


/*
function genRandomBigInt($length = 15, $formatted = true) {
    $characters = '0123456789';
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[)];
    }
    return rand(0, strlen($characters) - 1);
}*/


