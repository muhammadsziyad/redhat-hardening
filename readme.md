
## Hardening RHEL OS

This process focuses on improving security by implementing best practices such as disabling unnecessary 
services, applying security patches, configuring firewalls, and enabling auditing.

### Step-by-Step Guide for RHEL Hardening

#### 1. **Update the System**

-   Always keep the system updated with the latest security patches.

```
sudo yum update -y
``` 

#### 2. **Disable Unnecessary Services**

-   Identify and disable services that are not required.

```
systemctl list-unit-files --type=service
sudo systemctl disable <service_name>
sudo systemctl stop <service_name>
``` 

#### 3. **User and Password Security**

-   Enforce password complexity by configuring the `pam_pwquality` module.
-   Set password aging policies in `/etc/login.defs`.

**Example configuration:**


```
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_WARN_AGE   14
``` 

#### 4. **SSH Hardening**

-   Edit the `/etc/ssh/sshd_config` to disable root login and enforce key-based authentication.

```
PermitRootLogin no
PasswordAuthentication no
``` 

-   Restrict access to specific IPs by configuring firewall rules.

#### 5. **Firewall Configuration**

-   Configure `firewalld` to only allow necessary traffic.

```
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --reload
```

#### 6. **Enable SELinux**

-   SELinux adds an additional layer of security by enforcing mandatory access controls.
-   Ensure it is set to enforcing mode:

```
sudo setenforce 1
``` 

-   Check SELinux status and edit `/etc/selinux/config` to ensure it’s enabled:

`SELINUX=enforcing` 

#### 7. **Audit Logs**

-   Enable auditing to track system activities.

```
sudo yum install audit
sudo systemctl start auditd
sudo systemctl enable auditd
``` 

-   Review audit logs using `ausearch` or `aureport`.

#### 8. **Intrusion Detection System (IDS)**

-   Install and configure tools like `AIDE` (Advanced Intrusion Detection Environment) to monitor file 
integrity.

```
sudo yum install aide
sudo aide --init
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
``` 

#### 9. **Security-Enhanced Kernel Settings**

-   Harden kernel parameters by editing `/etc/sysctl.conf` to enable settings like disabling IP packet 
forwarding:

```
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 1
``` 

#### 10. **Enable Automatic Updates**

-   Configure automatic updates to ensure that your system is always up-to-date.

```
sudo yum install yum-cron
sudo systemctl enable yum-cron
sudo systemctl start yum-cron
``` 


### 11. **Limit Root Access**

-   Implement the **principle of least privilege** by creating specific user accounts for administrative 
tasks instead of using root.
-   Use `sudo` to grant temporary root privileges and log all `sudo` actions.
-   Edit the `/etc/sudoers` file to restrict which users can use `sudo` using `visudo` 


```
user_name ALL=(ALL) ALL
``` 

### 12. **Secure Boot Settings**

-   Ensure that BIOS/UEFI is configured to disable booting from external devices unless explicitly 
allowed.
-   Set a password on the bootloader (`GRUB`) to prevent unauthorized changes.

Edit `/etc/grub.d/40_custom` to set a GRUB password:

```
grub2-mkpasswd-pbkdf2
``` 

Then, add the output to the GRUB config.

### 13. **Configure File Permissions**

-   Audit critical system files and directories to ensure that permissions are correctly set, preventing 
unauthorized users from accessing sensitive data.

```
sudo chmod -R go-w /etc/
``` 

-   Set immutable flags on key system files (like `/etc/passwd` and `/etc/shadow`) to prevent accidental 
modifications.

```
sudo chattr +i /etc/passwd
sudo chattr +i /etc/shadow
``` 

### 14. **Enable Disk Encryption**

-   Encrypt sensitive data using Linux's native disk encryption (LUKS). If possible, encrypt entire disks 
or at least critical partitions, such as `/home`, `/var`, and `/etc`.

```
sudo cryptsetup luksFormat /dev/sdX
sudo cryptsetup luksOpen /dev/sdX encrypted_volume
``` 

### 15. **Enable Logging and Monitoring**

-   Install and configure monitoring tools such as `logwatch`, `rsyslog`, or `journald` to monitor system 
logs and detect unusual activity.

```
sudo yum install logwatch
sudo logwatch --detail High --mailto your_email@example.com --range All
``` 

-   Use centralized logging tools like **Graylog**, **ELK Stack**, or **Splunk** for better log analysis 
and alerting.

### 16. **Protect Against Denial of Service (DoS) Attacks**

-   Limit the number of connections to the server to mitigate the risk of a DoS attack by setting 
connection rate limits in `iptables`. Example for SSH:

```
sudo iptables -A INPUT -p tcp --dport 22 -m connlimit --connlimit-above 3 -j REJECT
``` 

### 17. **Configure Network Time Protocol (NTP)**

-   Ensure the system's time is accurate by synchronizing with trusted NTP servers. Accurate time is 
essential for maintaining log integrity and detecting anomalies.

```
sudo yum install chrony
sudo systemctl enable chronyd
sudo systemctl start chronyd
``` 

### 18. **Install Security Tools**

-   Consider additional tools like **Fail2Ban** to block IPs after repeated failed login attempts.

```
sudo yum install epel-release
sudo yum install fail2ban
sudo systemctl start fail2ban
sudo systemctl enable fail2ban
``` 

### 19. **Regular Backups**

-   Implement a robust backup strategy using tools like `rsync` or `tar`, and automate periodic backups to 
a secure location. Example using `tar`:

```
sudo tar -czf /backup/full_backup.tar.gz /important_data
``` 

-   Ensure backups are encrypted and stored securely offsite.

### 20. **Use MAC (Mandatory Access Control) Frameworks**

-   In addition to **SELinux**, consider other MAC frameworks like **AppArmor** (though not as widely used 
on RHEL) or configure custom SELinux policies for more granular control.

### 21. **Perform Regular Security Audits**

-   Use tools like **OpenSCAP** or **Lynis** for continuous security compliance and auditing:

```
sudo yum install scap-security-guide
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_rhel7 
/usr/share/xml/scap/ssg/content/ssg-rhel7-xccdf.xml
``` 

### 22. **Install and Enable Two-Factor Authentication (2FA)**

-   Add an additional layer of security by enabling 2FA for SSH using Google Authenticator.

```
sudo yum install google-authenticator
google-authenticator
``` 

-   Configure `/etc/pam.d/sshd` and `/etc/ssh/sshd_config` to use 2FA.


### 23. **Harden TCP/IP Stack**

-   Prevent various network-based attacks like IP spoofing and SYN flooding by configuring the TCP/IP 
stack.

Edit `/etc/sysctl.conf` with the following settings:

```
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
``` 

```
sudo sysctl -p
``` 

### 24. **Limit Open Ports**

-   Use `netstat` or `ss` to identify open ports, and close unnecessary ports to reduce the attack 
surface.

```
sudo ss -tuln
sudo firewall-cmd --remove-port=<port_number>/tcp --permanent
sudo firewall-cmd --reload
``` 

### 25. **Use Fail2Ban for Intrusion Prevention**

-   Install and configure Fail2Ban to block IP addresses with too many failed login attempts. This helps 
prevent brute-force attacks.
-   Example configuration for SSH (`/etc/fail2ban/jail.local`):

```
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/secure
maxretry = 5
bantime = 3600
``` 

### 26. **Protect Sensitive Files**

-   Secure key configuration files by setting appropriate ownership and permissions. For example:

```
sudo chown root:root /etc/ssh/sshd_config
sudo chmod 600 /etc/ssh/sshd_config
``` 

-   Lock down `/etc/fstab`, `/boot/grub2/grub.cfg`, and similar sensitive files:

```
sudo chattr +i /etc/fstab
sudo chattr +i /boot/grub2/grub.cfg
``` 

### 27. **Centralize Authentication**

-   Use centralized authentication with tools like LDAP, Kerberos, or Active Directory integration. This 
ensures consistent access control policies across multiple servers.

Example: Configuring LDAP client on RHEL:

```
sudo authconfig --enableldap --enableldapauth --ldapserver=ldap://ldap.example.com 
--ldapbasedn="dc=example,dc=com" --update
``` 

### 28. **Implement IPsec or VPN**

-   Use **IPsec** or **VPN** to secure data in transit between remote locations, especially when accessing 
the system remotely.
-   Set up IPsec for encrypting traffic:

```
sudo yum install libreswan
sudo ipsec setup start
``` 

### 29. **Enable AppArmor or SELinux Custom Policies**

-   While SELinux is already in use, you can create custom SELinux policies to restrict specific 
applications beyond the default policy.
-   Example of creating a custom SELinux policy:

```
sudo ausearch -c 'application_name' --raw | audit2allow -M myapp_policy
```
```
sudo semodule -i myapp_policy.pp
``` 

### 30. **Ensure Secure System Boot**

-   Implement **Secure Boot** to ensure that the system only runs signed bootloaders and kernels, 
preventing tampering.
-   Enable and configure **Trusted Boot** if supported by hardware to ensure integrity at startup.

### 31. **Configure Logging Retention and Rotation**

-   Configure log rotation to avoid logs filling up the disk, and ensure they are retained for a defined 
period.

Edit `/etc/logrotate.conf`:

```
/var/log/secure {
    weekly
    rotate 4
    create
    compress
    missingok
    notifempty
}
``` 

### 32. **Use Linux Kernel Hardening Features**

-   Enable **kernel self-protection mechanisms** such as stack protection, address space layout 
randomization (ASLR), and more.
-   Edit `/etc/sysctl.conf` to enable these:

```
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.exec-shield = 1
``` 

### 33. **Use Mandatory Access Control (MAC) for Containers**

-   If you're using containers, enforce MAC policies like SELinux or AppArmor within containerized 
environments.
-   Ensure containers do not run with elevated privileges and that they are isolated from the host.

### 34. **Install and Configure a Host Intrusion Detection System (HIDS)**

-   Use **OSSEC** or similar HIDS to monitor the integrity of the system, file changes, and security 
events.

```
sudo yum install ossec-hids
sudo systemctl start ossec-hids
``` 

### 35. **Enable FIPS Mode for Cryptographic Compliance**

-   If you're required to follow FIPS (Federal Information Processing Standards), enable FIPS mode to use 
only FIPS-approved cryptographic algorithms.

```
sudo fips-mode-setup --enable
sudo reboot
``` 

### 36. **Patch Management**

-   Implement a patch management process to ensure that updates are applied in a controlled manner, with 
the ability to roll back in case of issues.

### 37. **Remove Unnecessary Software**

-   Minimize the software installed on the system to reduce potential vulnerabilities by uninstalling any 
unused packages.

```
sudo yum list installed
sudo yum remove <package_name>
``` 

### 38. **Use Systemd Security Options**

-   Secure services started by `systemd` by using systemd security options. This can limit the privileges 
of services.

Example for securing a service: Edit the service file (e.g., `/etc/systemd/system/nginx.service`) and add:


```
[Service]
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
``` 

### 39. **Strengthen DNS Security**

-   Use **DNSSEC** to ensure DNS integrity and prevent DNS spoofing or poisoning.
-   Enable DNS over TLS (DoT) or DNS over HTTPS (DoH) for encrypted DNS traffic.

### 40. **Review System Logs Regularly**

-   Set up log review policies to regularly inspect logs for suspicious activity. Automate notifications 
for specific events via tools like **Logwatch** or **Nagios**.

```
sudo yum install nagios
``` 


### 41. **Enable Network Time Security (NTS)**

-   Use **Network Time Security (NTS)** to secure NTP (Network Time Protocol) communications, ensuring 
your system syncs with trusted sources and preventing time-based attacks.
-   NTS adds a layer of encryption and integrity checks, preventing attackers from manipulating time data.


```
sudo yum install chrony
```
Configure NTS support in /etc/chrony.conf:
```
server your-secure-ntp-server iburst nts
``` 

### 42. **Implement Multi-Factor Authentication (MFA)**

-   Beyond 2FA, you can integrate **MFA solutions** with hardware tokens, mobile applications, or 
biometric authentication.
-   Tools like **Duo Security** can integrate with SSH, RADIUS, and other services.

```
sudo yum install duo_unix
```
Configure in /etc/duo/duo.conf` 

### 43. **Use Security-Enhanced Linux Containers**

-   If you are running containers, ensure your container runtime is hardened. Consider using:
    -   **gVisor** or **Kata Containers** for additional isolation.
    -   **Podman** instead of Docker, since Podman runs containers rootless by default, improving 
security.

`sudo yum install podman` 

### 44. **Secure Network File System (NFS)**

-   If you use NFS, ensure the file-sharing protocol is properly secured by:
    
    -   Using **Kerberos authentication** with NFS.
    -   Limiting access based on IP or hostname in `/etc/exports`.
    -   Enabling encryption for NFS shares:
    
 ```
 /etc/exports:
   ```

```
/srv/nfs_share 192.168.1.0/24(rw,sync,sec=krb5p) 
```

-   Use version 4 of NFS, which has better security and performance features than older versions.

### 45. **Implement Endpoint Detection and Response (EDR)**

-   Install EDR tools like **CrowdStrike** or **Microsoft Defender for Linux** for real-time detection, 
prevention, and remediation of threats on the system.
-   These tools offer active monitoring and protection at the endpoint level, including malware detection, 
advanced threat protection, and automated response.

### 46. **Use Kernel Lockdown**

-   **Kernel Lockdown** is a security module that restricts certain actions that can modify the kernel, 
even from root. It is useful for protecting against persistent malware that tries to load unsigned kernel 
modules.


```
sudo grubby --update-kernel=ALL --args="lockdown=confidentiality"
sudo reboot
``` 

### 47. **Disable USB Ports for Unauthorized Devices**

-   Prevent unauthorized devices from being plugged into the system by disabling USB ports or only 
allowing authorized USB devices using tools like **USBGuard**.

```
sudo yum install usbguard
sudo systemctl start usbguard
sudo usbguard generate-policy > /etc/usbguard/rules.conf
sudo systemctl enable usbguard
``` 

### 48. **Enable Secure Boot with TPM (Trusted Platform Module)**

-   Use **TPM** to securely store encryption keys and ensure hardware-based security. Enable **TPM 2.0** 
with Secure Boot to prevent tampering with the boot process.
-   Install the `tpm-tools` package to manage TPM functionalities.

```
sudo yum install tpm-tools
sudo tpm_version
``` 

### 49. **Run a Bastion Host for Remote Access**

-   If SSH access is needed, use a **bastion host** to centralize access, reducing the exposure of your 
internal network.
-   A bastion host can be hardened to accept only pre-verified SSH connections and can monitor access more 
strictly.

### 50. **Application-Level Firewalls**

-   Deploy **Web Application Firewalls (WAFs)** for applications exposed to the web (like Apache, NGINX). 
These firewalls help protect against common web attacks such as SQL injection and Cross-Site Scripting 
(XSS).
-   Use tools like **ModSecurity** with NGINX or Apache.

```
sudo yum install mod_security
``` 

### 51. **Network Segmentation**

-   Implement **network segmentation** and **Virtual LANs (VLANs)** to isolate sensitive systems and data.
-   This limits the blast radius of a potential breach, ensuring attackers can't easily move laterally 
within your network.

### 52. **Use Immutable Infrastructure**

-   Consider using **immutable infrastructure** where system images are rebuilt from scratch for every 
change. This reduces configuration drift and minimizes potential vulnerabilities.
-   Combine this with **Infrastructure as Code (IaC)** tools like **Ansible** or **Terraform** for system 
provisioning and configuration.

### 53. **Host-based Intrusion Prevention Systems (HIPS)**

-   Use **HIPS** tools to actively prevent unauthorized changes and enforce security policies in 
real-time.
-   Examples include **Snort**, **Suricata**, or **OSSEC** configured with preventive rules.

### 54. **Compliance Automation Tools**

-   Use compliance automation tools like **OpenSCAP** to automatically check and remediate your RHEL OS 
based on industry standards like **CIS**, **HIPAA**, or **PCI-DSS**.
-   Example SCAP command for CIS benchmarks:

```
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis 
/usr/share/xml/scap/ssg/content/ssg-rhel8-xccdf.xml
``` 

### 55. **Automate Security Patch Management**

-   Automate patch deployment through tools like **Red Hat Satellite**, **Ansible**, or **YUM-cron**.
-   Implement automatic rollback mechanisms in case a patch causes system instability.

### 56. **Configure Role-Based Access Control (RBAC)**

-   Apply RBAC not just to users, but also for applications and services. Use **systemd** to restrict what 
each service can do through `systemd` service configuration files (e.g., `ProtectHome`, 
`NoNewPrivileges`).
-   Integrate with **SELinux** to enforce RBAC policies for services.

### 57. **Deploy Security Incident and Event Management (SIEM)**

-   Centralize log collection and monitoring through **SIEM** systems like **Splunk**, **Elastic Stack 
(ELK)**, or **Graylog**.
-   These tools help detect and correlate security events, providing real-time alerts and detailed 
analysis of incidents.

### 58. **Utilize Full Disk Encryption with LUKS**

-   Ensure full disk encryption using **LUKS** for any system that stores sensitive data. It can protect 
data at rest, especially for systems prone to theft or unauthorized physical access.
-   Example:

```
sudo cryptsetup luksFormat /dev/sdX
sudo cryptsetup luksOpen /dev/sdX encrypted_disk
``` 

### 59. **Ensure Secure Storage for Secrets**

-   Use **HashiCorp Vault**, **AWS Secrets Manager**, or **Azure Key Vault** to securely manage secrets 
such as API keys, passwords, and sensitive credentials.


### 60. **Use Disk Quotas**

-   Implement disk quotas to prevent users from consuming excessive disk space, which could lead to 
denial-of-service (DoS) conditions.
-   Enable quotas on the filesystem and configure them for users:

```
sudo yum install quota
sudo mount -o remount,usrquota /home
sudo quotacheck -cug /home
sudo quotaon /home
``` 

-   Edit `/etc/fstab` to make the quota persistent across reboots.

### 61. **Secure NFS (Network File System)**

-   If using NFS for sharing files, make sure to restrict access to trusted IP addresses and use strong 
authentication mechanisms.
-   Use `sec=krb5p` to enforce Kerberos authentication for NFS:

```
/etc/exports:
/nfs_share 192.168.1.0/24(rw,sync,no_root_squash,sec=krb5p)
``` 

-   Restart `nfs` service after configuration changes.

### 62. **Protect Network Services**

-   Secure network services by limiting access to trusted users or IPs using TCP wrappers and 
`hosts.allow`/`hosts.deny`.
-   Configure `/etc/hosts.allow` and `/etc/hosts.deny` to explicitly allow and deny connections from 
certain IP addresses. Example:

```
/etc/hosts.allow:
sshd: 192.168.1.10

/etc/hosts.deny:
ALL: ALL
``` 

### 63. **Configure Rate Limiting for SSH**

-   To prevent brute-force attacks, configure rate limiting for SSH using `firewalld` or `iptables`.

```
sudo firewall-cmd --permanent --add-rich-rule="rule family='ipv4' service name='ssh' limit value='5/m' 
accept"
sudo firewall-cmd --reload
``` 

### 64. **Disable USB Storage Devices**

-   Prevent unauthorized access via USB devices by disabling the `usb-storage` kernel module.

```
echo "blacklist usb-storage" | sudo tee /etc/modprobe.d/disable-usb-storage.conf
sudo dracut -f
``` 

### 65. **Implement Secure Time Synchronization with NTPsec**

-   NTPsec is a secure, hardened version of the Network Time Protocol daemon (ntpd) and should be used 
instead of the default NTP.

```
sudo yum install ntpsec
sudo systemctl enable ntpd
sudo systemctl start ntpd
``` 

### 66. **Enable DNSCrypt or DNS-over-TLS**

-   Use DNSCrypt or DNS-over-TLS to encrypt DNS traffic, preventing DNS spoofing and ensuring privacy in 
DNS queries.
-   Install and configure `dnscrypt-proxy` to route DNS queries securely:

```
sudo yum install dnscrypt-proxy
sudo systemctl enable dnscrypt-proxy
sudo systemctl start dnscrypt-proxy
``` 

### 67. **Use System-wide AppArmor Profiles**

-   Although primarily supported on Ubuntu, AppArmor can be configured on RHEL with some effort. It 
provides mandatory access control for applications.
-   Install AppArmor and create custom profiles for critical applications:

```
sudo yum install apparmor
``` 

### 68. **Limit Kernel Module Loading**

-   Restrict the loading of kernel modules by locking down `/etc/modprobe.d` and `/lib/modules`.
-   Use `modprobe` configurations to blacklist unwanted modules:

```
echo "install <module_name> /bin/true" | sudo tee /etc/modprobe.d/<module_name>.conf
``` 

### 69. **Use Strong Ciphers for OpenSSL and SSH**

-   Ensure that your system uses strong ciphers for encryption by configuring OpenSSL and SSH.
-   Edit `/etc/ssl/openssl.cnf` to disable weak ciphers:

```
[ default ]
CipherString = DEFAULT@SECLEVEL=2
``` 

-   For SSH, edit `/etc/ssh/sshd_config` to limit ciphers:

```
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
``` 

### 70. **Use Hardened Compilers**

-   Install and configure hardened compilers to mitigate vulnerabilities such as buffer overflows. GCC can 
be compiled with hardening flags like `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, and `-fPIE`.
-   Add these flags to your compiler’s makefiles to ensure binaries are built securely.

### 71. **Deploy Kernel Runtime Integrity Checking**

-   Tools like `Kernel Runtime Guard (KRGuard)` monitor for modifications in kernel memory space, helping 
to detect rootkits and other advanced kernel attacks.
-   Install and configure a kernel integrity checker

```
sudo yum install kpatch
``` 

### 72. **Implement Hardware Security Features**

-   Use hardware-based security features such as **Trusted Platform Module (TPM)** to store cryptographic 
keys securely.
-   If your server supports TPM, enable it in the BIOS/UEFI and configure it on RHEL.

### 73. **Install and Configure Bastille Linux**

-   **Bastille Linux** is a security hardening tool that audits the system and applies hardening measures. 
It's a powerful tool for automating and validating many security configurations.

```
sudo yum install bastille
sudo bastille -c
``` 

### 74. **Control USB and Peripheral Access with Udev Rules**

-   Write custom `udev` rules to allow or deny access to certain types of devices, such as USB drives or 
network cards.
-   For example, to disable USB storage devices:

```
ACTION=="add", SUBSYSTEMS=="usb", ATTR{authorized}="0"
``` 

### 75. **Remove Debugging Tools and Test Programs**

-   Remove all debugging and testing tools (like `gdb`, `strace`, or `lsof`) from production systems to 
prevent attackers from leveraging them.

```
sudo yum remove gdb strace lsof
``` 

### 76. **Use Multi-Factor Authentication (MFA) for Critical Systems**

-   Configure MFA for important system accounts, not just SSH. For example, enforce MFA for sudo 
operations or critical admin access via PAM (Pluggable Authentication Modules).
-   Install and configure **Google Authenticator** or a similar tool for MFA:

```
sudo yum install google-authenticator
``` 

### 77. **Use Tripwire for File Integrity Monitoring**

-   **Tripwire** is a widely-used file integrity monitoring tool that alerts you to unauthorized changes 
in files. It can monitor both system files and critical application data.

```
sudo yum install tripwire
sudo tripwire --init
sudo tripwire --check
``` 

### 78. **Configure Sandboxing for Applications**

-   Use **Bubblewrap** or similar sandboxing tools to run untrusted applications in isolated environments, 
limiting their ability to affect the system.

```
sudo yum install bubblewrap
bwrap --ro-bind /usr /usr --ro-bind /bin /bin --dev /dev bash
``` 

### 79. **Configure System Lockdown Mode**

-   RHEL 8 introduced **lockdown mode**, which prevents certain root capabilities to mitigate root-level 
attacks. You can enable it by editing the kernel boot parameters:

```
lockdown=integrity
```

### 61. **Configure ASLR (Address Space Layout Randomization)**

-   ASLR randomizes memory addresses, making it difficult for attackers to predict where system processes 
will reside in memory.


```
echo 2 > /proc/sys/kernel/randomize_va_space
``` 

### 62. **Enable ExecShield Protection**

-   Enable ExecShield to prevent buffer overflow exploits:


```
echo 1 > /proc/sys/kernel/exec-shield
``` 

### 63. **Limit Core Dumps**

-   Disable core dumps to prevent sensitive information leakage:


```
echo "* hard core 0" >> /etc/security/limits.conf
``` 

### 64. **Disable IPv6 if Not Needed**

-   If IPv6 is not required, disable it to reduce attack surface:


```
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p
``` 

### 65. **Limit User Processes (ulimit)**

-   Limit the number of processes users can create to prevent fork bombs:

```
echo "* hard nproc 100" >> /etc/security/limits.conf
``` 

### 66. **Enable SELinux Auditing for Critical Files**

-   Set up SELinux to audit critical files and directories:

```
sudo semanage fcontext -a -t auditd_log_t '/path/to/file(/.*)?'
``` 

### 67. **Configure GPG Check for Yum**

-   Ensure all installed packages are verified with GPG signatures:

```
echo "gpgcheck=1" >> /etc/yum.conf
``` 

### 68. **Configure AIDE (Advanced Intrusion Detection Environment)**

-   Use AIDE to monitor changes in system files and directories:

```
sudo yum install aide
sudo aide --init
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
sudo aide --check
``` 

### 69. **Use FIPS (Federal Information Processing Standards) Mode**

-   Enable FIPS mode to enforce cryptographic standards:

```
sudo fips-mode-setup --enable
``` 

### 70. **Disable X Window System**

-   If not needed, disable the X Window System to reduce attack surface:


```
sudo yum groupremove "X Window System"
``` 

### 71. **Secure Apache Web Server (if used)**

-   Secure Apache by disabling directory listing and limiting server info leakage:

```
sudo sed -i 's/Options Indexes/Options -Indexes/' /etc/httpd/conf/httpd.conf
sudo sed -i 's/ServerTokens OS/ServerTokens Prod/' /etc/httpd/conf/httpd.conf
``` 

### 72. **Enable Logging for sudo Commands**

-   Log all `sudo` commands to track privilege usage:

```
echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers
``` 

### 73. **Use Immutable Attribute for Key Configuration Files**

-   Apply the immutable flag to critical configuration files to prevent modification:

```
sudo chattr +i /etc/passwd /etc/shadow /etc/fstab
``` 

### 74. **Use Process Accounting**

-   Enable process accounting to track all executed commands:

```
sudo yum install psacct
sudo systemctl start psacct
sudo systemctl enable psacct
``` 

### 75. **Limit Cron Job Permissions**

-   Restrict who can create cron jobs by editing `/etc/cron.allow` and `/etc/cron.deny`:

```
sudo echo 'root' > /etc/cron.allow
``` 

### 76. **Disable Ctrl+Alt+Del Reboot**

-   Prevent accidental reboots by disabling the Ctrl+Alt+Del sequence:

```
sudo systemctl mask ctrl-alt-del.target
``` 

### 77. **Use Noexec, Nosuid, and Nodev Options for Mounting**

-   Mount `/tmp`, `/var`, and other partitions with security options:


```
echo "/dev/sda1 /tmp ext4 defaults,nosuid,noexec,nodev 0 0" >> /etc/fstab
``` 

### 78. **Use TCP Wrappers**

-   Control access to services with `/etc/hosts.allow` and `/etc/hosts.deny`:

```
echo "sshd: 192.168.1." >> /etc/hosts.allow
echo "ALL: ALL" >> /etc/hosts.deny
``` 

### 79. **Use CIS-CAT for Compliance Auditing**

-   Use the Center for Internet Security’s configuration auditing tool to scan and benchmark your system:

```
sudo yum install cis-cat
cis-cat.sh -b benchmark.xml
``` 

### 80. **Conduct Regular Vulnerability Scans**

-   Use tools like OpenSCAP or Nessus to conduct regular vulnerability scans on your system:

```
sudo yum install scap-workbench
```
