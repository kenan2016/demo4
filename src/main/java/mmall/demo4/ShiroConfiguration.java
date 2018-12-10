package mmall.demo4;

import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.Security;
import java.util.LinkedHashMap;

/**
 * @author kenan
 * @description shiro 配置类，要把认证、授权和密码校验规则注入到这个类里
 * @date 2018/12/6
 */
//SpringBoot 里这个注解的意思是项目启动时会自动配置这个类（是不是和加载配置文件一样）
//     这个配置类执行顺序 解释： 当项目启动的时候，或先加载配置shiroFilter 然后，shiroFilter配置  securityManager，securityManager配置
//             * authRealm， authRealm 又配置.... 这样一层一层的 配置下去，，，这里只是讲述 了 shiro的配置

// 再然后是配置 AuthorizationAttributeSourceAdvisor、  DefaultAdvisorAutoProxyCreator 形成 配置好shiro和 Spring之间的关系

@Configuration
public class ShiroConfiguration {

    /**
    * 单独解释一下   ("shiroFilter")  shiroFilter使用了我们自定义的 securityManager，
     * 而这个securityManager 又允许我们使用以自己期望的方式来验证一个用户
     * 另外这个 shiroFilter 还定义了我们登录的url 将以哪个拦截器处理，以及登录成功之后的url，以及我们任意一个 接口我们将做什么样的权限认证
     *
    */
    @Bean("shiroFilter") //这里其实就体现了shiro的权限配置
    public ShiroFilterFactoryBean shiroFilter(@Qualifier("securityManager") SecurityManager securityManager){
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        bean.setSecurityManager(securityManager);
        // 定义一些默认的请求的路径
        // 登录的url
        bean.setLoginUrl("/login");
        // 登录成功的url
        bean.setSuccessUrl("/index");
        // 无权限访问的时候跳转的url
        bean.setUnauthorizedUrl("/unauthorized");
        //下面是最和核心的配置：配置某些请求该怎么被拦截
        //String, String   key：代表一个正则表达式，代表的是我们访问的一个请求，value 代表我们使用什么样的拦截器
        // 一个拦截器链的map  filterChainDefinitionMap
        LinkedHashMap <String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        // 比如我们要求index  必须登录
        filterChainDefinitionMap.put("index","authc");// 这里含义是：对于index这个url 使用authc拦截器进行处理
        // 登录页面，拦截器配置
        filterChainDefinitionMap.put("/login", "anon");
        // 如果要实现，只要登录就口可以调用其他接口的的功能？？？其实我们只要将不需要校验的接口排除出去就行了  //loginUser  接口排除出去 就行了
        filterChainDefinitionMap.put("/loginUser", "anon");//loginUser 不需要做身份认证
        // 登录完成后其他接口都允许访问:下面的配置的解释：  这个拦截器表示：只要登录以后，所有接口都可以被访问
        // 可以看一下"user" 的意义  查看DefaultFilter.java
        filterChainDefinitionMap.put("/**", "user");//即所有的请求都会被拦截并判断一下是否登录，如果未登录会被指向登录页面

        // 另外我们怎么事项像spring security 里面的 某些接口只能被某一类角色访问呢？// 即不同角色访问不同url
        // 比如我们希望 /admin 这个接口只能 被角色为admin (这里校验的是角色名称，注意这里要把角色也要放到权限列表里、需要 实现以下)的用户访问，那么我们可以像下面写法：
        filterChainDefinitionMap.put("/admin", "roles[admin]");
        // 典型2：必须拿到 edit权才可以进行edit操作，这样的权限控制 》》》：具有了 edit 这个perms 才能访问 /edit

        ///拦截  druid/*  允许匿名请求：这个特例用来分析阿里巴巴 druid数据源中间件的性能
        filterChainDefinitionMap.put("/druid/**","anon");
        // 对于 druid 的学习建议读源码 DruidConfiguration

        //将定义好 的规则设置给  shiroFilter
        bean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return bean;
    }
    @Bean("securityManager")
    public SecurityManager securityManager(@Qualifier("authRealm") AuthRealm authRealm)  {
        DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
        manager.setRealm(authRealm);
        return manager;
    }

    @Bean("authRealm")
    public AuthRealm authRealm(@Qualifier("credentialMatcher") CredentialMatcher  matcher){
        AuthRealm authRealm = new AuthRealm();
        // 补充：使用缓存（这里的缓存是直接放到内存里的） 使用缓存以后我们所有的认证的东西都会被放到cach 里
        authRealm.setCacheManager(new MemoryConstrainedCacheManager());
        authRealm.setCredentialsMatcher(matcher);
        return  authRealm;
    }
    // 注解表示 这个 对象在 Spring 里的标识符
    @Bean("credentialMatcher")
    public CredentialMatcher credentialMatcher(){
        return new CredentialMatcher();
    }

    //配置一下shiro和spring之间的关联
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(@Qualifier("securityManager") SecurityManager securityManager){
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }

    //配置一下shiro和spring之间的关联，到这里shiro和Spring之间的 关联就是我们自己定制的了
    //代理
    @Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator(){
        DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator =new DefaultAdvisorAutoProxyCreator();
        defaultAdvisorAutoProxyCreator.setProxyTargetClass(true);//默认为false,这里设置为true
        return defaultAdvisorAutoProxyCreator;
    }

}
