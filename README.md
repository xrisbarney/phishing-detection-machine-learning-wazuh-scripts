# phishing-detection-machine-learning-wazuh-scripts

## About this project

## Contributors
- [@Spades0](https://github.com/Spades0) co-author.
- [@xrisbarney](https://github.com/xrisbarney) co-author.
- [@kahlflekzy](https://github.com/kahlflekzy) assisted with building the machine learning model and optimizing the URL extraction script.
- Nadezhda
- Ahmed

## Resources used
- [Shreyagopal URL feature extraction](https://github.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/blob/master/URL%20Feature%20Extraction.ipynb): We built on their URL features extraction script to create our own features extraction script.
- [Olafhartong's sysmon config](https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml): To capture victim endpoint logs.

## Tools used
- [Wazuh](https://github.com/wazuh/wazuh): An open source SIEM and XDR. This was used for detecting when a URL is opened, and its integration script subsequently determined if the URL was phishing or not.
- [Google Colab](https://colab.research.google.com/): Used for generating and training the model.
- [Phishtank](https://phishtank.org/): The phishing blacklist API used.
- [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon): For advanced logging.



## Set up
Below is a step-by-step implementation guide for integrating the phishing-detection ML scripts into your Wazuh deployment. This focuses on where to place files, what permissions they need, and which components run on the manager vs. the agent.

---

### 1. Prerequisites

* **Wazuh Manager**: v4.2.5 on Ubuntu (all-in-one install).
* **Wazuh Agent**: Installed on each Windows endpoint.
* **Sysmon**: Deployed on Windows endpoint to capture process-create events.

---

### 2. Endpoint (Agent) Configuration

1. **Install Wazuh Agent**
2. **Install Sysmon**
   Download the provided [`config.xml`](https://wazuh.com/resources/blog/emulation-of-attack-techniques-and-detection-with-wazuh/sysmonconfig.xml) and run:

   ```
   sysmon64.exe -i sysmonconfig.xml
   ```
3. **Tell the agent to forward Sysmon logs**
   In the agent’s `ossec.conf`, add:

   ```
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```

   Then restart the Wazuh agent.

---

### 3. Manager Configuration

All following steps run on the **Wazuh Manager**.

#### a. Place integration scripts & models

1. Copy the python integration into `/var/ossec/integrations/custom-phishing-detection.py`.
2. Copy the trained artifacts into the same directory:

   * `model.joblib`
   * `scaler.joblib`
3. Ensure the script is executable by Wazuh and not world-writable:

   ```
   chown root:ossec /var/ossec/integrations/custom-phishing-detection.py \
                      /var/ossec/integrations/model.joblib \
                      /var/ossec/integrations/scaler.joblib
   chmod 750 /var/ossec/integrations/custom-phishing-detection.py
   ```



#### b. Register the custom integration

In `/var/ossec/etc/ossec.conf`, under the `<integrations>` block, add:

```
<integration>
  <name>custom-phishing-detection.py</name>
  <hook_url>https://checkurl.phishtank.com/checkurl/</hook_url>
  <rule_id>100002</rule_id>
  <alert_format>json</alert_format>
</integration>
```

This tells the manager to invoke your script whenever rule **100002** fires.

#### c. Create detection rules

1. **Catch Chrome URL opens**
   In `/var/ossec/etc/rules/local_rules.xml`:

   ```
   <group name="phishing-algorithm">
     <rule id="100002" level="7">
       <if_sid>61603</if_sid>
       <field name="win.eventdata.commandLine" type="pcre2">(?i)chrome.exe</field>
       <description>URL was opened in Chrome: $(win.eventdata.commandLine).</description>
     </rule>
   </group>
   ```



2. **Alert if PhishTank blacklist finds a match**

   ```xml
   <group name="phishing-algorithm">
     <rule id="100003" level="10">
       <field name="phishtank.found" type="pcre2">^1$</field>
       <field name="phishtank.gotten_from" type="pcre2">^phishtank$</field>
       <description>A url opened by a user – $(phishtank.source.url) – was detected as phishing by PhishTank.</description>
     </rule>
   </group>
   ```



3. **Alert if ML model flags a URL**

   ```xml
   <group name="phishing-algorithm">
     <rule id="100004" level="10">
       <field name="phishtank.found" type="pcre2">^1$</field>
       <field name="phishtank.gotten_from" type="pcre2">^ml$</field>
       <description>$(phishtank.url) opened by a user has a $(phishtank.phish_percentage)% chance of being phishing.</description>
     </rule>
   </group>
   ```



#### d. Restart Wazuh Manager

```bash
systemctl restart wazuh-manager
```

---

### 4. Verification

1. **Open a known-bad URL** on the Windows agent.
2. **Check on the Wazuh dashboard** (or via `ossec.log`) for an alert from rule 100003.
3. **Open a suspicious new URL** (not in any blacklist) and verify rule 100004 fires with a ML-derived `%` score.

---

With this in place, all of the heavy lifting—URL extraction, blacklist lookup, feature-extraction, ML-prediction, and alert injection—runs on the **Wazuh Manager**, while the **agent** merely forwards Sysmon logs.

