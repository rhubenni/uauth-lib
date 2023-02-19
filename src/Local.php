<?php declare(strict_types=1);

namespace Rtelesco\UauthLib;

trait Local {
    
    

    /**
     * Valida a conta de usuário LOCAL no banco de dados
     * 
     * @param   int $udomain dominio da conta de usuário
     * @param   string $uname nome do usuário
     * @param   string $upass senha para acesso via autenticação UAuth local
     * @return  bool
     * @static
     */
    public static function local_credentials_check(int $udomain, string $uname, string $upass): bool
    {
        $sql = "
            SELECT  accountuser
            FROM    datacore_uauth.accounts
            WHERE   accountserverid = :server
                    AND accountname = :accname
                    AND localpassword = :accpass
        ";
        $stmt = self::$conn->prepare($sql);
        $stmt->bindValue("server", $udomain);
        $stmt->bindValue("accname", $uname);
        $stmt->bindValue("accpass", \hash('sha512', $upass));
        $check = $stmt->executeQuery();
        
        // TODO: Verificar retorno
        if ($check) {
            $r =  $check->num_rows;
            $check->close();
            return ($r === 1) ? true : false;
        }
        return false;
    }
    
}
