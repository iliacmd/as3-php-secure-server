<?php


class FactoryAPI{

    public static function callMethod( $name, $args ){

        switch( $name ){

            case 'hello':
                return FactoryAPI::hello( $args[0] );
            break;

        }

    }

    private static function hello( $name ){
        return "Hello," . $name;
    }


}
