package mmall.demo4;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;

/**
 * @author kenan
 * @description
 * @date 2018/12/6
 * 一个最基本的密码校验规则的重写
 */
public class CredentialMatcher extends SimpleCredentialsMatcher{
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
        // 拿到 usernamePasswordToken 里的密码。
        String password = new String(usernamePasswordToken.getPassword());
        // 拿到 数据库里的密码
        String dbUserPwassword = (String) info.getCredentials();
        return this.equals(password,dbUserPwassword);
    }
}
