#!/bin/bash


javac -cp .:bcprov-ext-jdk18on-172.jar Crypto.java
javac Timer.java
java -cp .:bcprov-ext-jdk18on-172.jar Crypto

echo "Script Executed Sucessfully!"