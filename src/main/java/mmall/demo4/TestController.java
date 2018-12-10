package mmall.demo4;

import mmall.demo4.model.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpSession;

/**
 * @author kenan
 * @description shiro测试controller
 * @date 2018/12/8
 */
@Controller
public class TestController {
    @RequestMapping("/login")
    public String login() {
        return "login";
    }

    @RequestMapping("/index")

    public String index() {
        return "index";
    }
    @RequestMapping("/loginUser")
    public String loginUser(@RequestParam("username") String username
            , @RequestParam("password") String password, HttpSession session){
        // 使用uername和password创建 shiro 里的 usernamePasswordToken 对象
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username, password);
        try {
            Subject subject = SecurityUtils.getSubject();
            //下面开始编写shiro的认证逻辑
            subject.login(usernamePasswordToken);// 这里会进行认证
            //认证完成后，获取user  Principal 主体  就是登陆用户
            User user = (User) subject.getPrincipal();
            session.setAttribute("user", user);// 当设置好 这个user 以后 会在 authRelm里取到 （src\main\java\mmall\demo4\AuthRealm.java）
            return "index";//这里的index 会被 解析成index页面
        } catch (Exception e) {
            return "login";
        }

    }

    @RequestMapping("/loginout")
    public String loginout(){
        Subject subject = SecurityUtils.getSubject();
        if (subject != null) {
            //登出时需要判断一下当前用户是否为空。如果为空则说明已退出。如果不为空，说明未退出，然后执行退出（？是为了防止空指针？？）
            subject.logout();
        }
        return "login";
    }

    @RequestMapping("/unauthorized")
    public String unauthorized () {
        return "unauthorized";
    }

    @RequestMapping("/admin")
    @ResponseBody
    public String admin () {
        return "admin success";
    }

}
