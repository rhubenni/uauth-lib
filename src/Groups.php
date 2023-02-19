<?php declare(strict_types=1);

namespace Rtelesco\UAuth;

trait Groups {
    
    /**
     * Retorna o ID numérico de determinado grupo
     * 
     * @param   string $name nome do grupo
     * @return  int|bool id do grupo, ou falso, caso o grupo não exista
     * @static
     */
    public static function get_group_id(string $name) : bool|int
    {
        
        $stmt = self::$conn->prepare("SELECT `gid` FROM `datacore_uauth`.`groups` WHERE `groupname` = :gname");
        $stmt->bindValue("gname", $name);
        $resultSet = $stmt->executeQuery();
        if(!$resultSet) {
            return false;
        }
        return $resultSet->fetchOne();
    }
    
    
    /**
     * Lista os usuários associados a um determinado grupo
     * 
     * @param   int|string $group id ou nome do grupo
     * @return  array com os usuários do grupo informado
     * @static
     */
    public static function get_group_users(int|string $group) : array
    {
        if(\is_int($group)) {
            $gid = $group;
        } else {
            $gid = self::get_group_id($group);
        }
        if(!$gid) {
            return [];
        }
        self::get_connection();
        $stmt = self::$conn->prepare("SELECT `userid` FROM `datacore_uauth`.`groupassign` WHERE `gid` = :gid");
        $stmt->bindValue("gid", $gid);
        $resultSet = $stmt->executeQuery();
        if(!$resultSet) {
            return [];
        }
        return $resultSet->fetchAllAssociative();
    }
    
}