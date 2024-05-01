#!/bin/bash
release_os="/etc/os-release"
cent_command=firewalld
ubuntu_command=ufw

if grep "Ubuntu" $release_os
then
   echo "------------------------------------------------"
   sudo apt update -y
   sudo apt install ifupdown -y
   sudo apt install python3-pip -y
   sudo pip3 install Flask 
   sudo apt install iptables -y
   if command -v $ubuntu_command
   then
     sudo ufw disable
     sudo apt remove ufw -y
     sudo apt purge ufw -y
     echo "Ufw Removed Completed."
   else
     echo "Ufw Uninstalled."
   fi
   echo " "
   echo "------------------------------------------------"
   echo "OS Ubuntu: All Services Installations Completed."
   echo "------------------------------------------------"
fi

if grep "CentOS" $release_os
then
   echo "------------------------------------------------"
   sudo yum update -y
   sudo yum install python3-pip -y
   sudo pip3 install Flask
   sudo yum install iptables-services -y
   if command -v $cent_command
   then
     sudo systemctl stop firewalld
     sudo systemctl disable firewalld
     yum remove firewalld -y
     echo "Firewalld Removed Completed."
   else
     echo "Firewalld Uninstalled."
   fi
   echo " "
   echo "------------------------------------------------"
   echo "OS CentOS: All Services Installations Completed."
   echo "------------------------------------------------"
fi