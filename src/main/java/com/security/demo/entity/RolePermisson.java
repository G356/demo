package com.security.demo.entity;

import lombok.Data;

@Data
public class RolePermisson {

    private String url;
    private String roleName;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }


}
