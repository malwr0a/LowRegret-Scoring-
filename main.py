import os
import requests
import pandas as pd
import time
import csv
import json


def readcsv(file):
    """
    Reads in a CSV file and grabs the iocs
    :param file: csv file
    :return: hashes, ips, domains
    """
    hashes = []
    domains = []
    ips = []
    df = pd.read_csv(file, index_col=0, header=None)
    for key, value in df.iterrows():
        if key == 'ip':
            ips.append(value.item())
        elif key == 'domain':
            domains.append(value.item())
        elif key == 'hash':
            hashes.append(value.item())
        else:
            pass
    return hashes, ips, domains


def writecsv(prefix, keys, data):
    """
    Writes out csv file
    :param prefix: str the type of ioc data for csv title
    :param keys: list csv headers
    :param data: csv_writter the data which will be me written
    """
    with open(prefix + '_output.csv', 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(data)



def readFile(file):
    """
    reads a file and returns the contents
    :param file: file object
    :return: contents of the file
    """
    with open(file, 'r') as f:
        data = f.read()
    return data


class VirusTotal:
    """
    VirusTotal class contains functions need to return data.
    """
    def __init__(self, secret):
        self.secret = secret
        self.vt_base = "https://virustotal.com/api/v3/"
        self.vt_header = {'x-apikey': self.secret}
        self.ipend = f"ip_addresses/"
        self.domend = f"domains/"
        self.hashend = f"files/"

    def vt_engine_malware(self, results):
        """
        searches virustotal because and reutnr the last analysis results
        :param results: dictionary
        :return: list of vt results
        """
        ngnMalware = []
        if 'data' in results:
            for engine, ngnR in results['data']['attributes']['last_analysis_results'].items():
                if 'malicious' in ngnR['category'] or 'suspicious' in ngnR['category']:
                #if ngnR['result'] not in ['clean', 'unrated']:
                    ngnMalware.append(engine)
                    #print(ngnR)
        #print(ngnMalware)
        return ngnMalware


    def vt_domain_popularity(self, results):
        """
        searches for
        :param results:
        :return:
        """
        for key, value in results['data']['attributes']['popularity_ranks'].items():
            return value['rank']
        return -1


    def vt_ip_resolve(self, ip):
        """
        Looks up an IP in vt and to see if its resolves to an domain
        :param ip: string
        :return: returns vt response
        """
        r = requests.get(self.vt_base + self.ipend + ip + "/resolutions", headers=self.vt_header, verify=False)
        return r.json()['data']

    def vt_ioc_get_details(self, endpoint, ioc):
        """
        Looks up IOC in vt and returns response
        :param endpoint: str, vt endpoint to search against
        :param ioc: str, ioc being searched
        :return: if the there is a status code of 200 it returns
        """
        r = requests.get(self.vt_base + endpoint + ioc, headers=self.vt_header, verify=False)
        # if r.status_code == 200:
        return r.json()
        # else:
        #     print(f'failed to get {ioc}')



    def vt_hash_process(self, hash):
        """
        processes ioc hash and returns the processed results.
        :param hash: str, hash being investigated
        :return: dict, processed results
        """
        hashDetails = self.vt_ioc_get_details(self.hashend, hash)
        numNgn = self.vt_engine_malware(hashDetails)
        if (len(numNgn) >= 1):
            return {'hash': hash, 'score': 'LowRegret', "NumberEngFlagged": len(numNgn)}
        elif knownGoodHash(hash) == "HighRegret":
            return {'hash': hash, 'score': 'HighRegret', "NumberEngFlagged": len(numNgn)}
        elif 'error' in hashDetails:
            return {'hash': hash, 'score': 'Undefined ', "NumberEngFlagged": 'no data entry'}
        else:
            return {'hash': hash, 'score': 'Undefined', "NumberEngFlagged": len(numNgn)}


    def vt_ip_process(self, ip, badASN):
        """
        Pocesses ips being lookedup
        :param ip: str, ip being looked up
        :param badASN: file, list of known bad ASns
        :return: dict, processed results of hash
        """
        ip_details = self.vt_ioc_get_details(self.ipend, ip)
        ip_resolve = self.vt_ip_resolve(ip)
        numNgn = self.vt_engine_malware(ip_details)
        ASN = "AS"
        if 'asn' in ip_details['data']['attributes']:
            ASN = ASN + str(ip_details['data']['attributes']['asn'])

        if len(numNgn) > 0 and ASN in badASN and len(ip_resolve) <= 2:
            return {'ip': ip, 'score': 'LowRegret', "NumberEngFlagged": len(numNgn),
                    'NumberDomainsResolved': len(ip_resolve)}
        else:
            return {'ip': ip, 'score': 'Undefined', "NumberEngFlagged": len(numNgn),
                    'NumberDomainsResolved': len(ip_resolve)}
        # if (len(numNgn) == 0):
        #     return {'ip': ip, 'score':'Undetermined',"NumberEngFlagged": len(numNgn), 'NumberDomainsResolved': len(ip_resolve)}
        #
        # # If reputation is bad then;
        # else:
        #     # Look up ASN, and check aginst bad list
        #     # if ASN is not bad , set to Undetermined
        #     if ASN not in badASN:
        #         return {'ip': ip, 'score': 'Undetermined', "NumberEngFlagged": len(numNgn), 'NumberDomainsResolved': len(ip_resolve)}
        #     # If ASN is bad, check domain resoluation,
        #     else:
        #         # if 2 or less than set to low regret
        #         if len(ip_resolve) <= 2:
        #             return {'ip': ip, 'score': 'LowRegret', "NumberEngFlagged": len(numNgn),'NumberDomainsResolved': len(ip_resolve)}
        #         # if more than 2 set Undetermined
        #         else:
        #             return {'ip': ip, 'score':'Undetermined',"NumberEngFlagged": len(numNgn), 'NumberDomainsResolved': len(ip_resolve)}

        # Sources:
        # VT for reputation and dns info
        # return vt_reputation


    def vt_process_domains(self, domain, domainAge, dcd):
        """
        Processes domain data
        :param domain: str, domain being processed
        :param domainAge: int, age of domain from void
        :param dcd: str, domain created date.
        :return: return of processed results
        """
        domainDetails = self.vt_ioc_get_details(self.domend, domain)
        numNgn = self.vt_engine_malware(domainDetails)
        rank_score = self.vt_domain_popularity(domainDetails)
        if rank_score >= 0 & rank_score <= 1000000:
            return {'domain': domain, 'score': 'HighRegret', 'NumberEngFlagged': len(numNgn), 'domain_age': domainAge,
                    'creation_date': dcd}
        elif domainAge <= 30:
            return {'domain': domain, 'score': 'LowRegret', 'NumberEngFlagged': len(numNgn), 'domain_age': domainAge,
                    'creation_date': dcd}
        # elif domainAge >= 180:
        elif domainAge > 30 and len(numNgn) >= 1:
            return {'domain': domain, 'score': 'LowRegret', 'NumberEngFlagged': len(numNgn), 'domain_age': domainAge,
                    'creation_date': dcd}
        else:
            unknown = {'domain': domain, 'score': "Undefined", 'NumberEngFlagged': len(numNgn),
                       'domain_age': domainAge, 'creation_date': dcd}
            if unknown['domain_age'] == 111 and len(numNgn) >= 1:
                unknown['score'] = "LowRegret"
                unknown['domain_age'] = "Domain Registered, Flagged as malicious"
                unknown['creation_date'] = 'no data entry ip void'
            elif unknown['domain_age'] == 111 and len(numNgn) == 0:
                unknown['score'] = "LowRegret"
                unknown['domain_age'] = "Domain Registered, no data entry ip void"
                unknown['creation_date'] = 'no data entry ip void'
            elif unknown['domain_age'] == 99 and len(numNgn) >= 1:
                unknown['score'] = "LowRegret"
                unknown['domain_age'] = 'no data in IP Void'
                unknown['creation_date'] = 'no data in IP Void'
            elif unknown['domain_age'] == 99 and len(numNgn) == 0:
                unknown['score'] = "LowRegret"
                unknown['domain_age'] = 'no data in IP Void'
                unknown['creation_date'] = 'no data in IP Void'
            else:
                pass
            return unknown


def apivoid(domain, key):
    """
    Looks up domain in Void
    :param domain: str, domain to search
    :param key: str, key for apivoid
    :return: json, returns response
    """
    r = requests.get("https://endpoint.apivoid.com/domainage/v1/pay-as-you-go/?key=" + key + "&host=" + domain)
    return r.json()


def processDomain(secretsFile, data):
    """
    processes domain data
    :param secretsFile: dict, json key file
    :param data:
    :return: returns processed results
    """
    results = []
    vt = VirusTotal(secretsFile['virustotal'])
    for domain in data:
        rvoid = apivoid(domain, secretsFile["void"])
        if 'error' not in rvoid.keys() and rvoid['data']['domain_registered'] == 'yes':
            domainAge = rvoid['data']['domain_age_in_days']
            domainCreationDate = rvoid['data']['domain_creation_date']
        elif 'error' not in rvoid.keys() and rvoid['data']['domain_registered'] == 'no':
            domainAge = 111
            domainCreationDate = 111
        else:
            domainAge = 99
            domainCreationDate = 99
        result = vt.vt_process_domains(domain, domainAge, domainCreationDate)
        results.append(result)
        time.sleep(5)
    return results


def processIps(secretsFile, ips, badASN):
    """
    processes ips passed.
    :param secretsFile: dict, json keys
    :param ips: list, ips being processed
    :param badASN: file, file of  known bad ASN
    :return:
    """
    results = []
    for ip in ips:
        vt = VirusTotal(secretsFile['virustotal'])
        result = vt.vt_ip_process(ip, badASN)
        results.append(result)
    return results


def knownGoodHash(hash):
    """
    Checks hash against Cicl.lu for known good hashes
    :param hash: str, hash being lookuped
    :return: returns either hi or low regret
    """
    c_url = "https://hashlookup.circl.lu/lookup/"
    kgr = requests.get(c_url + hash, verify=False)
    if kgr.status_code == 200:
        return "HighRegret"
    else:
        return "LowRegret"


def processHash(secretsFile, hashes):
    """
    processes hashes
    :param secretsFile: dict, json keys
    :param hashes: list of hashes being processed
    :return: results of the processed hashes
    """
    results = []
    for hash in hashes:
        vt = VirusTotal(secretsFile['virustotal'])
        result = vt.vt_hash_process(hash)
        print(result)
        results.append(result)
    return results


def main():
    """
    main function for processing iocs and writing output to csv and stix
    """
    secretsFile = input("secrets file: ")
    f = open(secretsFile, 'r')
    secrets = json.load(f)
    ioccsv = input("drop ioc csv file: ")
    hashes, ips, domains = readcsv(ioccsv)
    if len(hashes) > 0:
        results = processHash(secrets, hashes)
        keys = results[0].keys()
        writecsv(prefix='hashes_', keys=keys, data=results)
    if len(ips) > 0:
        # read asn file
        f = open('BadASN.txt', 'r')
        badASN = f.read().split('\n')
        results = processIps(secrets, ips, badASN)
        keys = results[0].keys()
        writecsv(prefix='ips_', keys=keys, data=results)
    if len(domains) > 0:
        results = processDomain(secrets, domains)
        keys = results[0].keys()
        writecsv(prefix='domains_', keys=keys, data=results)


#kicks of script
if __name__ == "__main__":
    main()
