# Tripwire
 A lightweight container for monitoring suricata logs and sending emails via MS365 Graph

Note that the docker-compose hosted on Github includes a pull and config of suricata with default ruleset, as well as evebox for local web based GUI for suricata. 

The main difference between this repo and a normal Suricata/Evebox deployment is the inclusion of the Tripwire alerting logic to integrate email sending and log parsing/alerting logic into the stack. 
