# AVL-Firewall Solution

AVL-Firewall is a lightweight firewall application designed to provide essential network security functionalities. Built with Python, it offers a simple and efficient solution for controlling traffic flow. Key features encompass a user-friendly web GUI interface, seamless integration with iptables for traffic management, and flexible rule management enabling rule addition and removal. Additionally, it automatically saves logs into files for comprehensive monitoring.

**Front-End** : HTML, CSS, JS | **Back-End** : Python, Flask, JSON

[![My Skills](https://skillicons.dev/icons?i=html,css,js,python,flask)](https://skillicons.dev)

Compatible with both **Ubuntu** and **CentOS**, setting up AVL-Firewall merely requires the addition of two interfaces.

![](https://github.com/chathuracsd/Project-Images/blob/main/AVL-FW-Diagram.jpg)

## Set Environment

Use this to set up your environment.

https://medium.com/@mayankgajera3/nat-network-address-translation-481d59cef1ee

## Deploy Application

#### Run the Bash Script

```
sh package-install.sh
```

Set the inside and outside interfaces in **firewall-code.py**

Use **ifconfig** command to view interfaces

```
wan_int = "ens38"
lan_int = "ens33"

```

#### Run the Python Script

```
python firewall-code.py
```

#### Get Web GUI interface

Web URL **http://localhost:3004**

![](https://github.com/chathuracsd/Project-Images/blob/main/AVL-Firewall-Start.jpg)
