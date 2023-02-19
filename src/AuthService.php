<?php declare(strict_types=1);

namespace Rtelesco\UauthLib;


use \Doctrine\DBAL\Connection;
use \Symfony\Component\Yaml\Yaml;
use \Doctrine\DBAL\DriverManager;
use \Rtelesco\UAuth\ProviderLDAP AS LDAP;
use \Rtelesco\Cybel\JSON;
use \Rtelesco\Cybel\HTTP;

/**
 * AuthService
 * Classe para controle de permissões e autenticação de usuários com suporte LDAP
 * 
 * @staticvar resource $conn interno de conexão ao banco de dados
 * @staticvar array $current_user dados do usuário atual
 * @staticvar string $last_permission_message última mensagem de validação
 * @version 2.23.2-17.draft
 */

class AuthService
{
    
    private static Connection|null $conn = null;
    public static string $_configFile = '';
    private static array $_config = [];
    public static $current_user;
    public string $last_permission_message = '';
    
    use Accounts;
    use Error;
    use Groups;
    use Local;
    use Permissions;
    use Timeout;
    use Users;
    
    /**
     * Obtem conexão ao banco de dados
     * @param string|null $config arquivo YAML com as definições do banco de dados
     * 
     * @static
     */
    private static function get_connection(): void
    {
        if(!self::$conn) {
            $yaml = self::$_configFile ?? dirname(__FILE__) . DIRECTORY_SEPARATOR . 'uauthconf.yaml';
            if(!\file_exists($yaml)) {
                throw new \Exception("The config file for UATHLIB don't seems to exists :/");
            }
            self:: $_config = Yaml::parseFile($yaml ?? self::$_configFile);
            self::$conn = DriverManager::getConnection(self::$_config['database_connection']);
        }
    }
    
    /**
     * Obtem lista de provedores de autenticação configurados
     * 
     * @return  array lista de servidores confirgurados para uso com a lib
     * @static
     */
    public static function list_servers(): array
    {
        self::get_connection();
        $sql = "SELECT serverid, displayname, serverdomain FROM cfg_ldapservers";
        return self::$conn->fetchAllAssociative($sql);
    }
    
    /**
     * Efetua logout
     *
     * @static
     */
    public static function do_logout($redirect = '/?logout'): void
    {
        foreach ($_SESSION as $key => $value) {
            unset($_SESSION[$key]);
        }
        session_regenerate_id();
        HTTP\Headers::redirect($redirect, false);
    }
    
    /**
     * Efetua o processo de autenticação via LDAP e checa a validação da conta
     * no banco de dados
     * 
     * @param   string $uname nome do usuário
     * @param   string $upass senha do usuário
     * @param   int $udomain dominio no qual a autenticação deve ser realizada
     * @return  bool
     * @static
     */
    public static function do_login(string $uname, string $upass, int $udomain): bool
    {
        self::get_connection();
        $sql = "SELECT serverid, servername, serverdomain, searchfilter, islocaldevelopment "
                . "FROM cfg_ldapservers WHERE serverid = ?";
        $domain = self::$conn->prepare_select($sql, 'i', [$udomain], 1);

        if ($domain[0]['servername'] && $domain[0]['islocaldevelopment']) {
            $allowSelRegister = false;
            $login = self::local_credentials_check($udomain, $uname, $upass);
        }

        if ($domain[0]['servername'] && !$domain[0]['islocaldevelopment']) {
            $allowSelRegister = self::$uauth_options['allow_self_register'];
            $login = LDAP::connect(
                $domain[0]['servername'],
                $domain[0]['serverdomain'],
                $uname,
                $upass,
                $domain[0]['searchfilter']
            );
        }

        if ($login) {
            if ($domain[0]['islocaldevelopment']) {
                $update_ldap_info = false;
            } else {
                $update_ldap_info = true;
            }
            $account_exists = self::check_account($udomain, $uname, $allowSelRegister, $update_ldap_info);
            LDAP::disconnect();
            if ($account_exists) {
                return self::session_data();
            }
        }
        return false;
    }

    /**
     * Cria e popula a sessão de dados do usuário autenticado
     * 
     * @return  bool
     * @static
     */
    public static function session_data(): bool
    {
        if (!self::$current_user['account'] || !self::$current_user['userid']) {
            \Cybel\Core\Sessions\renew();
            return false;
        }

        $udomain_name = self::$conn->prepare_select("
            SELECT      serverdomain
            FROM        datacore_uauth.cfg_ldapservers
            WHERE       serverid = ?
        ", 'i', [self::$current_user['udomain']], 1)[0]['serverdomain'];

        $_SESSION['AuthService'] = [
            'account'       => self::$current_user['account'],
            'user'          => self::$current_user['userid'],
            'adinfo'        => LDAP::$user_info ?? self::$current_user,
            'udomain'       => self::$current_user['udomain'],
            'udomain_name'  => $udomain_name
        ];
        self::renew_timeout();
        return true;
    }
    
    
}
