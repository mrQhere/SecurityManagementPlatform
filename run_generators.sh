for tool in "Metasploit:msfconsole:High" "RouterSploit:rsf:High" "Responder:responder:Critical" "SQLNinja:sqlninja:High" "Impacket:impacket:High" "OpenVAS:openvas:High" "Arachni:arachni:Medium" "W3AF:w3af_console:High" "Golismero:golismero:Medium" "Snallygaster:snallygaster:High" "Bandit:bandit:Medium" "Brakeman:brakeman:Medium" "OSVScanner:osv-scanner:High" "KubeBench:kube-bench:High" "DetectSecrets:detect-secrets:High"; do
    IFS=":" read -r name bin sev <<< "$tool"
    python3 tools/create_scanner.py --name "$name" --binary "$bin" --severity "$sev"
done
