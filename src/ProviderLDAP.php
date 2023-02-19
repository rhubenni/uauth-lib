<?php declare(strict_types=1);

namespace Rtelesco\UAuth;


class ProviderLDAP
{

    protected static $ldap;
    public static $user_info;

    public static function connect(
        string $server,
        string $domain,
        string $user,
        string $pass,
        string $searchfilter
    ): bool
    {
        self::$ldap = \ldap_connect($server);

        $adUser = $domain . '\\' . $user;

        \ldap_set_option(self::$ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
        \ldap_set_option(self::$ldap, LDAP_OPT_REFERRALS, 0);

        $bind = @\ldap_bind(self::$ldap, $adUser, $pass);

        if (!$bind) {
            return false;
        } else {
            self::get_user_info($user, $searchfilter);
            return true;
        }
    }

    public static function get_user_info($user, $searchfilter): array
    {
        $filter = "(sAMAccountName={$user})";
        $result = \ldap_search(self::$ldap, $searchfilter, $filter);
        #\ldap_sort($ldapConn,$result,"sn");
        $info = \ldap_get_entries(self::$ldap, $result);
        if (key_exists('count', $info[0]['memberof'])) {
            unset($info[0]['memberof']['count']);
        }
        self::$user_info = [
            'name'              => $info[0]['cn'][0],
            'title'             => $info[0]['title'][0] ?? '',
            'department'        => $info[0]['department'][0] ?? '',
            'mail'              => $info[0]['mail'][0] ?? '',
            'mobile'            => $info[0]['mobile'][0] ?? '',
            'samaccountname'    => $info[0]['samaccountname'][0],
            'document1'         => $info[0]['matricula'][0],
            'document2'         => null,
            // TODO port generate_var
            'ldapgroups'        => JSON::generate_var($info[0]['memberof'])
        ];

        return self::$user_info;
    }

    public static function disconnect(): void
    {
        if (self::$ldap) {
            \ldap_close(self::$ldap);
        }
    }
}