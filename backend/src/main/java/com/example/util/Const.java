package com.example.util;

public enum Const {
    BLACK_LIST("blackList:"),

    ;


    final String name;

    private Const(String name) {
        this.name = name;
    }

    public String getName() {
        return "jwt:" + name;
    }
}
