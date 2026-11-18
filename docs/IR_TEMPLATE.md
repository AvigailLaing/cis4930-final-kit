# Incident response write-up template

One of these per thing you handled. The blue packet grades you on five, so keep them short and complete rather than long.
Two allowed kinds: a misconfiguration you found and fixed, or an indicator of compromise you found and reversed.

---

## Incident N: <one line title>

**Kind:** misconfiguration / vulnerability / indicator of compromise
**Host:** Twin Peaks PD / Calhoun Memorial Hospital
**Time:** detected at __:__ , resolved at __:__
**Detected by:** the exact tool or log, e.g. `aureport -k cron`, `ss -tupn`, Sysmon event 13, Wazuh rule 100104

### What it was
Two or three sentences. What the thing is, and why it mattered here.

### Evidence
- Screenshot reference (Figure __)
- The command that showed it, verbatim

```
<command and the interesting output>
```

### What I did about it
Containment and removal, in order, with commands.

### Proof it is gone
Screenshot after the fix, plus the re-check a minute later. If it came back, say so and name the second mechanism,
because that is the strongest sentence in the whole report.

### How Red got there, or how it would have been prevented
For a misconfiguration: what setting allowed it, and the permanent fix.
For an IOC: which technique this maps to, and what a defender should have seen earlier.

---

### Reminder: the four fields, live
```
IOC:   what it was
WHERE: machine + path
TOOL:  what showed it
TIME:  the minute
```
