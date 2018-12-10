package mmall.demo4;

import mmall.demo4.model.Permission;
import mmall.demo4.model.Role;
import mmall.demo4.model.User;
import mmall.demo4.service.UserService;
import org.apache.commons.collections.CollectionUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * @author kenan
 * @description 自定义realm实现认证和授权
 * @date 2018/12/6
 */
public class AuthRealm  extends AuthorizingRealm{
    @Autowired
    private UserService userService;
    //授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        // 这个写法相当于从session里获取到用户
        User user = (User)principalCollection.fromRealm(this.getClass().getName()).iterator().next();
        // 获取权限列表
        List<String> permissionList = new ArrayList<>();
        List<String> roleNameList = new ArrayList<>();
         Set<Role> roleSet = user.getRoles();
        if (CollectionUtils.isNotEmpty(roleSet)) {
            for (Role role : roleSet) {
                roleNameList.add(role.getRname());
                Set<Permission> permissionSet = role.getPermissions();
                if (CollectionUtils.isNotEmpty(permissionSet)) {
                    for (Permission permission : permissionSet) {
                        permissionList.add(permission.getName());
                    }
                }
            }
        }
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        // 权限  授权
        simpleAuthorizationInfo.addStringPermissions(permissionList);
        //角色授权
        simpleAuthorizationInfo.addRoles(roleNameList);

        // 其实是哈可以实现不同的接口使用不同的权限来控制
        return simpleAuthorizationInfo;
    }
    // 认证登录
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) authenticationToken;
        String usrname = usernamePasswordToken.getUsername();
        User user = userService.findByUsername(usrname);
        return new SimpleAuthenticationInfo(user, user.getUsername(), this.getClass().getName());
    }
}
