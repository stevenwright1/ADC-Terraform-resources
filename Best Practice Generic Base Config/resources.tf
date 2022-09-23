

###################################
# A few things you can't do (yet).
###################################

#Create HA pair

###############################
#  All the things we can do.
###############################

# Set the hostname
resource "citrixadc_nshostname" "tf_nshostname" {
   hostname = "mycitrix_adc"
}

# Create VLAN, add SNIP, bind SNIP to VLAN
resource "citrixadc_vlan" "tf_vlan" {
  vlanid    = 40
  aliasname = "Important data VLAN"
}

resource "citrixadc_vlan_interface_binding" "tf_bind" {
  vlanid = citrixadc_vlan.tf_vlan.vlanid
  ifnum  = "0/1"
  tagged = "true"
}

resource "citrixadc_nsip" "tf_snip" {
  ipaddress  = "10.0.0.1"
  type       = "SNIP"
  netmask    = "255.255.255.0"
  icmp       = "ENABLED"
  mgmtaccess = "DISABLED"
}

resource "citrixadc_vlan_nsip_binding" "tf_bind" {
  vlanid    = citrixadc_vlan.tf_vlan.vlanid
  ipaddress = citrixadc_nsip.tf_snip.ipaddress
  netmask   = citrixadc_nsip.tf_snip.netmask
}

#7. HA failsafe mode is enabled to ensure that the last healthy node continues to provide service
# Note that you will want to define the secondary node in provider.tf and run similar commands as settings like failsafe mode need to be implemented on both HA nodes.
resource "citrixadc_hanode" "primary_node_ha_failover" {
  hanode_id = 0 //the id of primary_node is always 0
  failsafe  = "ON"
}

#8. Restrict HA failovers to 3 in 1200 seconds
resource "citrixadc_hanode" "primary_node_ha_maxfliptime" {
  hanode_id   = 0 //the id of primary_node is always 0
  maxfliptime = 1200
}

resource "citrixadc_hanode" "primary_node_ha_maxflips" {
  hanode_id = 0 //the id of primary_node is always 0
  maxflips  = 3
}


# 10. Make sure you can ping each SNIP with Mac Based Forwarding (MBF) is disabled or that you understand why you cannot
resource "citrixadc_nsmode" "tf_nsmode_mbf_off" {
  mbf = false
}

# 11. You have installed a new SSL certificate and key for the management GUI within Traffic Management, SSL, Certificates
resource "citrixadc_systemfile" "certificate1_crt_file" {
  filename     = "certificate1.crt"
  filelocation = "/nsconfig/ssl"
  filecontent  = file("certificate1.crt")
}

resource "citrixadc_systemfile" "certificate1_key_file" {
  filename     = "certificate1.key"
  filelocation = "/nsconfig/ssl"
  filecontent  = file("certificate1.key")
}

#Add SSL cert to ADC
resource "citrixadc_sslcertkey" "tf_sslcertkey" {
  certkey            = "tf_sslcertkey"
  cert               = "/nsconfig/ssl/certificate1.crt"
  key                = "/nsconfig/ssl/certificate1.key"
  notificationperiod = 40
  expirymonitor      = "ENABLED"
}

resource "citrixadc_sslservice_sslcertkey_binding" "tf_sslservice_sslcertkey_binding_nshttps-127_0_0_1-443" {
  certkeyname = citrixadc_sslcertkey.tf_sslcertkey.certkey
  servicename = "nshttps-127.0.0.1-443"
}

resource "citrixadc_sslservice_sslcertkey_binding" "tf_sslservice_sslcertkey_binding_nshttps-__1l-443" {
  certkeyname = citrixadc_sslcertkey.tf_sslcertkey.certkey
  servicename = "nshttps-::1l-443"
}

resource "citrixadc_sslservice_sslcertkey_binding" "tf_sslservice_sslcertkey_binding_nsrpcs-127_0_0_1-3008" {
  certkeyname = citrixadc_sslcertkey.tf_sslcertkey.certkey
  servicename = "nsrpcs-127.0.0.1-3008"
}

resource "citrixadc_sslservice_sslcertkey_binding" "tf_sslservice_sslcertkey_binding_nsrpcs-__1l-3008" {
  certkeyname = citrixadc_sslcertkey.tf_sslcertkey.certkey
  servicename = "nsrpcs-::1l-3008"
}

resource "citrixadc_sslservice_sslcertkey_binding" "tf_sslservice_sslcertkey_binding_nskrpcs-127_0_0_1-3009" {
  certkeyname = citrixadc_sslcertkey.tf_sslcertkey.certkey
  servicename = "nskrpcs-127.0.0.1-3009"
}

#resource "citrixadc_sslvserver_sslcertkey_binding" "tf_binding" {
#  vservername = citrixadc_lbvserver.tf_lbvserver.name
#  certkeyname = citrixadc_sslcertkey.tf_sslcertkey.certkey
#  snicert     = true
#}


#Base configuration settings

#1. Set the timezone and enable NTP
# Merged with item 12

#2. Create a Key Encryption Key
# Command depreciated and modern firmware, now automatic

#3. Set a non-default nsroot password
resource "citrixadc_systemuser" "tf_user" {
  username = "nsroot"
  password = "secret"
}

#4. Add an account for ADM with external authentication disabled
resource "citrixadc_systemuser" "admuser" {
  username     = "admuser"
  password     = "admpassword"
  externalauth = "DISABLED"
  timeout      = 900
  cmdpolicybinding {
    policyname = "superuser"
    priority   = 100
  }
}

#5. Restrict non-management applications access to the NSIP and only HTTPS access
resource "citrixadc_nsip" "tf_nsip" {
  ipaddress      = "192.168.9.10"
  netmask        = "255.255.0.0"
  gui            = "SECUREONLY"
  restrictaccess = "ENABLED"
}

#6. Set a non-default RPC node password

#resource "citrixadc_nsrpcnode" "tf_nsrpcnode_secondary" {
#  ipaddress = "192.168.9.11"
#  password  = "verysecret"
#  secure    = "ON"
#}

#resource "citrixadc_nsrpcnode" "tf_nsrpcnode_primary" {
#  ipaddress = "192.168.9.10"
#  password  = "verysecret"
#  secure    = "ON"
#}

#9. Disable SSLv3 and TLS1 for management services

resource "citrixadc_sslservice" "nshttps-__1l-443" {
  servicename = "nshttps-::1l-443"
  ssl3        = "DISABLED"
  tls1        = "DISABLED"
}

resource "citrixadc_sslservice" "nshttps-127_0_0_1-443" {
  servicename = "nshttps-::1l-443"
  ssl3        = "DISABLED"
  tls1        = "DISABLED"
}

#10. Set generic modes and features
resource "citrixadc_nsmode" "tf_nsmode_generic" {
  l3   = false
  edge = false
}

resource "citrixadc_nsfeature" "tf_nsfeature" {
  lb        = true
  ssl       = true
  rewrite   = true
  responder = true
  cmp       = true
}

#11. Configure one or more DNS nameserver

resource "citrixadc_lbmonitor" "tf_lbmonitor_DNS_UDP_monitor" {
  monitorname = "DNS_UDP_monitor"
  type        = "DNS"
  query       = "."
  querytype   = "Address"
  lrtm        = "DISABLED"
  interval    = "6"
  resptimeout = "3"
  downtime    = "20"
  destport    = "53"
}

resource "citrixadc_lbvserver" "tf_lbvserver_DNS" {
  name            = "DNS_UDP"
  persistencetype = "NONE"
  servicetype     = "DNS"
}

resource "citrixadc_servicegroup" "tf_servicegroup_DNS" {
  servicegroupname    = "DNS_UDP_SVG"
  servicetype         = "DNS"
  servicegroupmembers = ["1.1.1.1:53:10", "8.8.8.8:53:10"]
  lbvservers          = [citrixadc_lbvserver.tf_lbvserver_DNS.name]
}

resource "citrixadc_servicegroup_lbmonitor_binding" "tf_binding_DNS" {
  servicegroupname = citrixadc_servicegroup.tf_servicegroup_DNS.servicegroupname
  monitorname      = citrixadc_lbmonitor.tf_lbmonitor_DNS_UDP_monitor.monitorname
  weight           = 80
}

resource "citrixadc_lbmonitor" "tf_lbmonitor_DNS_TCP_monitor" {
  monitorname = "DNS_TCP_monitor"
  type        = "DNS-TCP"
  query       = "."
  querytype   = "Address"
  lrtm        = "DISABLED"
  interval    = "6"
  resptimeout = "3"
  downtime    = "20"
  destport    = "53"
}

resource "citrixadc_lbvserver" "tf_lbvserver_DNS_TCP" {
  name            = "DNS_TCP"
  persistencetype = "NONE"
  servicetype     = "DNS_TCP"
}

resource "citrixadc_servicegroup" "tf_servicegroup_DNS_TCP" {
  servicegroupname    = "DNS_TCP_SVG"
  servicetype         = "DNS_TCP"
  servicegroupmembers = ["1.1.1.1:53:10", "8.8.8.8:53:10"]
  lbvservers          = [citrixadc_lbvserver.tf_lbvserver_DNS_TCP.name]
}

resource "citrixadc_servicegroup_lbmonitor_binding" "tf_binding_DNS_TCP" {
  servicegroupname = citrixadc_servicegroup.tf_servicegroup_DNS_TCP.servicegroupname
  monitorname      = citrixadc_lbmonitor.tf_lbmonitor_DNS_TCP_monitor.monitorname
  weight           = 80
}

resource "citrixadc_dnsnameserver" "dnsnameserver_UDP" {
  dnsvservername = "DNS_UDP"
  state          = "ENABLED"
  type           = "UDP"
}

resource "citrixadc_dnsnameserver" "dnsnameserver_TCP" {
  dnsvservername = "DNS_TCP"
  state          = "ENABLED"
  type           = "TCP"
}

#12. Set TCP and HTTP parameters
resource "citrixadc_nstcpparam" "tf_tcpparam" {
  ws    = "ENABLED"
  sack  = "ENABLED"
  nagle = "ENABLED"
}

resource "citrixadc_nshttpparam" "tf_nshttpparam" {
  dropinvalreqs   = "ON"
  markhttp09inval = "ON"
}

resource "citrixadc_nsparam" "tf_nsparam_cookie" {
  cookieversion = "1"
  timezone      = "CoordinatedUniversalTime"
}

resource "citrixadc_ntpserver" "tf_ntpserver" {
  servername          = "pool.ntp.org"
  minpoll            = 6
  maxpoll            = 10
  preferredntpserver = "YES"
}

resource "citrixadc_ntpsync" "tf_ntpsync" {
  state = "ENABLED"
}

#13. Restrict SNMP queries to select servers
resource "citrixadc_snmpmanager" "tf_snmpmanager" {
  ipaddress          = "192.168.2.4"
  netmask            = "255.255.255.255"
}

#14. Set SNMP alarms and traps
resource "citrixadc_snmpalarm" "tf_snmpalarm" {
  trapname       = "CPU-USAGE"
  thresholdvalue = 80
  normalvalue    = 35
  state          = "ENABLED"
  severity       = "Informational"
  logging        = "ENABLED"
}

resource "citrixadc_snmpalarm" "tf_snmpalarm1" {
  trapname       = "MEMORY"
  thresholdvalue = 80
  normalvalue    = 35
  state          = "ENABLED"
  severity       = "Critical"
  logging        = "ENABLED"
}

resource "citrixadc_snmpalarm" "tf_snmpalarm2" {
 trapname       = "HA-STATE-CHANGE"
 severity       = "Critical"
}

resource "citrixadc_snmptrap" "tf_snmptrap" {
  trapclass       = "generic"
  trapdestination = "192.168.2.2" // SNMPTRAPDSTIP
  communityname   = "public"
}

#15. Set a remote syslog server

resource "citrixadc_auditsyslogaction" "tf_syslogaction" {
  name       = "tf_syslogaction"
  serverip   = "10.78.60.33"
  serverport = 514
  loglevel = [
    "ALL"
  ]
}
resource "citrixadc_auditsyslogpolicy" "tf_auditsyslogpolicy" {
  name   = "tf_auditsyslogpolicy"
  rule   = "ns_true"
  action = "tf_syslogaction"

  globalbinding {
    priority       = 120
    feature        = "SYSTEM"
    globalbindtype = "SYSTEM_GLOBAL"
  }
}

#16. Set a timeout and prompt for management sessions
resource "citrixadc_systemparameter" "tf_systemparameter" {
    timeout = 900
}

resource "citrixadc_systemparameter" "tf_systemparameter1" {
  promptstring = "%u@%h-%s"
}

#17. Centralized authentication for management accounts

resource "citrixadc_authenticationldapaction" "tf_authenticationldapaction" {
  name                    = "ldapaction"
  serverip                = "1.2.3.4"
  serverport              = 636
  ldapbase                = "<dc=mycoolcompany,dc=local>"
  ldapbinddn              = "<serviceaccount@mycoolcompany.local>"
  ldapbinddnpassword      = "LDAPPASSWORD"
  ldaploginname           = "sAMAccountName"
  searchfilter            = "&(|(memberOf:1.2.840.113556.1.4.1941:<cn=Citrix-ADC-FullAccess,ou=groups,dn=mycoolcompany,dc=local>)(memberOf:1.2.840.113556.1.4.1941:<cn=Citrix-ADC-ReadOnly,ou=groups,dn=mycoolcompany,dc=local>))"
  groupattrname           = "memberOf"
  subattributename        = "cn"
  sectype                 = "SSL"
  passwdchange            = "ENABLED"
  nestedgroupextraction   = "ON"
  maxnestinglevel         = "5"
  groupnameidentifier     = "samAccountName"
  groupsearchattribute    = "memberOf"
  groupsearchsubattribute = "CN"
}

resource "citrixadc_authenticationldappolicy" "tf_authenticationldappolicy" {
  name      = "tf_authenticationldappolicy"
  rule      = "ns_true"
  reqaction = citrixadc_authenticationldapaction.tf_authenticationldapaction.name
}

resource "citrixadc_systemgroup" "tf_systemgroup_Citrix-ADC-FullAccess" {
  groupname = "Citrix-ADC-FullAccess"
  timeout   = 900

  cmdpolicybinding {
    policyname = "superuser"
    priority   = 100
  }
}

resource "citrixadc_systemgroup" "tf_systemgroup_Citrix-ADC-ReadOnly" {
  groupname = "Citrix-ADC-ReadOnly"
  timeout   = 900

  cmdpolicybinding {
    policyname = "read-only"
    priority   = 110
  }
}

#18. Disable LDAP authentication for the nsroot user

resource "citrixadc_systemuser" "nsroot_externalauth_disable" {
  username     = "nsroot"
  externalauth = "DISABLED"
}
