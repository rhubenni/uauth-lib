<?php declare(strict_types=1);

namespace Rtelesco\UAuth;

trait Error {
    
    
    /**
     * Retorna mensagem de erro no formato html ou json
     * 
     * @param   string $errortype tipo de erro a ser retornado impresso
     * @return  void
     * @static
     */
    public static function print_error(string $errortype = 'json') : void
    {
        switch ($errortype) {
            case 'html':
                HTTP\Headers::response_code(401);
                die('<h1>Sessão expirada</h1> <br /> <a href="/?expired=true">Clique aqui para efetuar login novamente.</a>');
                break;
            case 'json':
                JSON::json_print([
                    'error' => [
                        'code' => 403,
                        'message' => 'Não autorizado.'
                    ]
                ], 403, true);
                die();
                break;
            default:
                die();
                break;
        }
    }
    
}