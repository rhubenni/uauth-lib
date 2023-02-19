<?php declare(strict_types=1);

namespace Rtelesco\UauthLib;

trait Users {
    
    
    
    /**
     * Cria novo usuário
     * 
     * @param   array $userdata dados do usuário (obtidos via LDAP)
     * @param   bool $autoregister define se o usuário foi criado por auto registro
     * @return  int id do usuário criado
     * @todo    implementar gravação da flag de autoregistro em banco de dados
     * @static
     */
    public static function create_user(array $userdata, bool $autoregister): int
    {
        self::get_connection();
        $sql = "
                INSERT INTO users
                (
                    name,
                    title,
                    department,
                    email,
                    mobile,
                    document1,
                    document2,
                    ldapgroups,
                    createdby,
                    updatedby
                )
                VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ";
        
        // TODO check if $userdata is indexed or associtative
        $stmt = self::$conn->prepare($sql);
        $stmt->bindValue(0, $userdata[0]);
        $stmt->bindValue(1, $userdata[1]);
        $stmt->bindValue(2, $userdata[2]);
        $stmt->bindValue(3, $userdata[3]);
        $stmt->bindValue(4, $userdata[4]);
        $stmt->bindValue(5, $userdata[5]);
        $stmt->bindValue(6, $userdata[6]);
        $stmt->bindValue(7, $userdata[7]);
        $stmt->bindValue(8, $userdata[8]);
        $stmt->bindValue(9, $userdata[9]);
        $stmt->executeQuery();
        
        return self::$conn->lastInsertId();
    }
    
    /**
     * Atualiza usuário
     * 
     * @param   array $userdata dados do usuário (obtidos via LDAP)
     * @param   bool $autoregister define se o usuário foi criado por auto registro
     * @return  bool
     * @todo    implementar gravação da flag de autoregistro em banco de dados
     * @static
     */
    public static function update_user(int $uid, array $userdata): void
    {
        $userdata[] = $uid;
        self::get_connection();
        self::$conn->update(
            'users',
            [
                // TODO check if $userdata is indexed or associtative
                'name'              => $userdata[0],
                'title'             => $userdata[1],
                'department'        => $userdata[2],
                'email'             => $userdata[3],
                'mobile'            => $userdata[4],
                'document1'         => $userdata[5],
                'document2'         => $userdata[6],
                'ldapgroups'        => $userdata[7],
                'updatedby'         => $userdata[8],
            ],
            [
                'userid'            => $userdata[9],
            ]
        );
        return;
    }
}