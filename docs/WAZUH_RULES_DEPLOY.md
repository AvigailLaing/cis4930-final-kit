# Deploying the custom Wazuh rules

Try A first: it needs no shell on the Wazuh box.

## A. GUI, always available

1. Open https://172.16.10.254, log in (admin / Owls4TW*26).
2. Management -> Rules -> Custom rules -> Add new rule.
3. Paste the whole group block from blue/wazuh_local_rules.xml.
4. Save. The rule appears with its id (100100 and up).
5. Test it with the ruleset tester (wazuh-logtest in the UI) on a real event.

If a rule never fires, the parent id is wrong: read the id that actually matched and set if_sid to it.

## B. CLI, only if SSH to the Wazuh box works

    scp blue/wazuh_local_rules.xml agentcooper@172.16.10.254:/tmp/
    ssh agentcooper@172.16.10.254
    sudo cp /tmp/wazuh_local_rules.xml /var/ossec/etc/rules/final_custom_rules.xml
    sudo /var/ossec/bin/wazuh-analysisd -t
    sudo /var/ossec/bin/wazuh-control restart

If SSH is refused, use A. Do not burn round time on it.

## Addresses

Wazuh: https://172.16.10.254      Scoring: https://172.16.10.250:8443      both out of scope for red
