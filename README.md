# LowRegret-Scoring
This project is to score IoCs based on LowRegret model. 
Reference: https://github.com/JHUAPL/Low-Regret-Methodology
## Contributors:
* Arwa Alomari https://github.com/malwr0a/
* Spenser https://github.com/sandcatintel/
## Installation 
```
git clone https://github.com/malwr0a/LowRegret-Scoring-
```
## Requiremnts 
To use LowRegret-Scoring you should insert VirusTotal and IPVoid into secrets.json file with the following format:
```
  {"virustotal": "YOUR_API_KEY", "void": "YOUR_API_KEY"}

```
Then, drop <IOCs_file_name>.csv file with the following format:

| type   | value        |
|--------|--------------|
| ip     | <IP_IoC>     |
| domain | <Domain_IoC> |
| hash   | <Hash_IoC>   |

The APIs can be requested on the respective service websites:
* Virus Total (community and paid API): https://www.virustotal.com/gui/join-us
* IPVoid: https://www.ipvoid.com/threat-intelligence-apis/
