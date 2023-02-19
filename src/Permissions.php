<?php declare(strict_types=1);

namespace Rtelesco\UAuth;

trait Permissions {
    
    /**
     * Cria nova flag de permissão
     *
     * @param string $flag Nome da nova flag de permissão
     * @param string $description Descrição da nova flag de permissão
     * @return  bool|int
     * @static
     */
    public static function create_new_permission(string $flag, string $description): int|bool
    {
        if ($flag !== '' || $description !== '') {
            self::$conn->insert('permissions_flags', [
                'permissionflag' => $flag,
                'permissiondesc' => $description
            ]);
            return self::$conn->lastInsertId();
        } else {
            return false;
        }
    }
    
    /**
     * Valida usuário ROOT e validade da sessão
     * 
     * @return  bool TRUE em caso de sucesso, FALSE em caso de falha
     * @static
     */
    public static function check_root(): bool
    {
        $status = self::check_timeout();
        $check = self::check_permission_flag('ROOT_USER');
        return (!$status || !$check) ? false : true;
    }
    
    
    /**
     * Verifica permissões do usuário
     * 
     * @param   string|array $flag flag da permissão a ser verificada (ou array)
     * @return  bool TRUE em caso de sucesso, FALSE em caso de falha
     * @static
     */
    public static function check_permission_flag(string|array $flag): bool
    {
        if (!\is_array($flag)) {
            $flag = [$flag];
        }
        self::get_connection();
        $uid = (int) ($_SESSION['AuthService']['user'] ?? null);
        if (!$uid || $uid === 0) {
            return false;
        }
        $sql = "
                SELECT      *
                FROM        vw_permissions
                WHERE       userid = :uid
                            AND permissionflag = :flag
                LIMIT       1
        ";
        foreach ($flag as $key => $value) {
            $stmt = self::$conn->prepare($sql);
            $stmt->bindValue("uid", $uid);
            $stmt->bindValue("flag", $value);
            $result = $stmt->executeQuery()->rowCount();
            $return = ($result) > 0 ? true : false;
            if ($return) {
                $stmt->closeCursor();
                return true;
            }
            $stmt->closeCursor();
        }
        return false;
    }
    
    /**
     * Verifica permissões do usuário e validade da sessão
     * 
     * @param   string|array $flag flag da permissão a ser verificada (ou array com várias permissões)
     * @param   string $errortype tipo de erro a ser retornado, caso exista
     * @param   bool $destroy_session sessão autial deve ser destruída, caso permissão seja negada?
     * @return  bool TRUE em caso de sucesso, FALSE em caso de falha
     * @static
     */
    public static function check_permission(string|array $flag = null, string $errortype = 'bool', bool $destroy_session = false): bool
    {
        $status = self::check_timeout();
        if ($flag == null) {
            $check = true;
            self::$last_permission_message = 'Timeout renewed';
        } else {
            $check = self::check_permission_flag($flag);
            if (!$check) {
                $check = self::check_root();
                self::$last_permission_message = 'Timeout renewed / ROOT Access granted';
            }
        }

        if (!$status) {
            self::$last_permission_message = 'Sessão encerrada por inatividade. Efetue o login novamente.';
        }
        if (!$check) {
            self::$last_permission_message = 'Usuário sem autorização para executar esta ação.';
        }

        if (
            !isset($status) ||
            !$status ||
            !isset($_SESSION['AuthService']) ||
            !$check
        ) {
            if ($destroy_session) {
                \Cybel\Core\Sessions\renew();
            }
            self::print_error($errortype);
        }
        return (!$status || !$check) ? false : true;
    }


    /**
     * Obtem os usuários que possuem a permissão informada
     * 
     * @param   string $permissionflag flag da permissão
     * @return  array com os usuários com a permissão informado
     * @static
     */
    public static function get_permission_users(string $permissionflag) : array
    {
        self::get_connection();
        $sql = "
            SELECT DISTINCT `userid`
            FROM `datacore_uauth`.`vw_permissions`
            WHERE `permissionflag` = :flag
        ";
        $stmt = self::$conn->prepare($sql);
        $stmt->bindValue("flag", $permissionflag);
        $resultSet = $stmt->executeQuery();
        return $resultSet->fetchAllAssociative();
    }
}
