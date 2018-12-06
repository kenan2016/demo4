package mmall.demo4.service;


import mmall.demo4.model.User;

public interface UserService {

    User findByUsername(String username);
}
