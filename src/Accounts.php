<?php declare(strict_types=1);

namespace Rtelesco\UauthLib;

trait Accounts {
    
    
    /**
     * Valida a conta de usuário no banco de dados
     * 
     * @param   int $udomain dominio da conta de usuário
     * @param   string $uname nome do usuário
     * @param   bool $autoregister define se o modo de auto registro é permitido
     * @param   bool $update_ldap_info define se o usuário deve ser atualizado à partir dos registros LDAP
     * @return  bool
     * @static
     */
    public static function check_account(int $udomain, string $uname, bool $autoregister = false, bool $update_ldap_info = false): bool
    {
        self::get_connection();
        $sql = "
                SELECT      accountid,
                            accountserverid,
                            accountname,
                            accountuser,
                            userid,
                            name
                FROM        accounts
                INNER JOIN  users
                ON          accounts.accountuser = users.userid
                WHERE       accountserverid = :server
                            AND accountname = :accname
        ";
        
        $stmt = self::$conn->prepare($sql);
        $stmt->bindValue("server", $udomain);
        $stmt->bindValue("accname", $uname);
        
        $resultSet = $stmt->executeQuery();
        $account = $resultSet->fetchAllAssociative();
        
        // TODO: fix LDAP info

        if ($account && $update_ldap_info) {
            self::update_user(
                $account[0]['userid'],
                [
                    LDAP::$user_info['name'],
                    LDAP::$user_info['title'],
                    LDAP::$user_info['department'],
                    LDAP::$user_info['mail'],
                    LDAP::$user_info['mobile'],
                    LDAP::$user_info['document1'],
                    LDAP::$user_info['document2'],
                    LDAP::$user_info['ldapgroups']
                ]
            );
            $account = self::$conn->prepare_select($sql, 'is', [$udomain, $uname], 1);
        }

        if ($account) {
            self::$current_user['udomain'] = $account[0]['accountserverid'];
            self::$current_user['account'] = $account[0]['accountid'];
            self::$current_user['userid'] = $account[0]['userid'];
            self::$current_user['name'] = $account[0]['name'];
            return true;
        } else if (!$account && $autoregister) {
            $uid = self::create_user([
                LDAP::$user_info['name'],
                LDAP::$user_info['title'],
                LDAP::$user_info['department'],
                LDAP::$user_info['mail'],
                LDAP::$user_info['mobile'],
                LDAP::$user_info['document1'],
                LDAP::$user_info['document2'],
                LDAP::$user_info['ldapgroups'],
                1,
                1
            ], true);
            if ($uid) {
                $aid = self::register_account((int) $udomain, LDAP::$user_info['samaccountname'], $uid, 1);
                if ($aid) {
                    self::$current_user['account'] = $aid;
                    self::$current_user['userid'] = $uid;
                    return true;
                }
            }
        }
        return false;
    }
    
    /**
     * Cria nova conta
     * 
     * @param   int $accountserverid servidor ao qual a conta está vinculada
     * @param   string $accountname nome da conta de usuário
     * @param   int $accountuserid id do usuário vinculado a conta
     * @param   int $createdby id do usuário responsável pela criação da conta
     * @param   string $localpassword senha do usuário (para conta local)
     * @return  int id da conta de usuário
     * 
     * @static
     */
    public static function register_account(int $accountserverid, string $accountname, int $accountuserid, int $createdby, string $localpassword = '#;Integrated;0x00'): int
    {
        self::get_connection();
        $sql = "
                INSERT INTO accounts
                (accountserverid, accountname, localpassword, accountuser, createdby)
                VALUES
                (:server, :accname, :localpass, :uid, :createdby)
        ";
        $stmt = self::$conn->prepare($sql);
        $stmt->bindValue("server", $accountserverid);
        $stmt->bindValue("accname", $accountname);
        $stmt->bindValue("localpass", $localpassword);
        $stmt->bindValue("uid", $accountuserid);
        $stmt->bindValue("createdby", $createdby);
        $stmt->executeQuery();
        return self::$conn->lastInsertId();
    }
}
