<?php declare(strict_types=1);

namespace Rtelesco\UauthLib;

trait Timeout {
    
    
    /**
     * Renova o tempo limite para expiração da sessão de usuário ativa
     * 
     * @return  void
     * @static
     */
    public static function renew_timeout(): void
    {
        $_SESSION['AuthService']['timeout'] = time() + self::$uauth_options['timeout'];
    }
    
    
    /**
     * Verifica se a requisição está dentro do prazo de validade da sessão de usuário
     * ativa, ou se a mesma expirou
     * 
     * @return  bool
     * @static
     */
    public static function check_timeout(): bool
    {
        if (isset($_SESSION['AuthService']) && $_SESSION['AuthService']['timeout'] > \time()) {
            self::renew_timeout();
            $status = true;
        } else {
            $status = false;
        }
        return $status;
    }
    
    
}
