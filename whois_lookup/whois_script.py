import whois
import os

Target_Domain = input("Domain 입력을 해주세요 : ")

information = whois.whois(Target_Domain)

result_memo = str(information)

safe_filename = Target_Domain.replace(".", "_") + ".txt"

with open(safe_filename, "w", encoding="utf-8") as f:
    f.write(result_memo)

full_path = os.path.abspath(safe_filename)
os.system(f"notepad {full_path}")



print("\n해당 Target_Domain의 정보")
print("\n도메인 이름 :", information["domain_name"])
print("\n등록 기관:", information["registrar"])
print('\nURL:', information["registrar_url"])
print('\nwhois_server:', information["whois_server"])
print('\nupdated_date:',information["updated_date"])
print('\ncreation_date:',information["creation_date"])
print('\nexpiration_date:',information["expiration_date"])
print('\nname_servers:',information["name_servers"])
print("")
print('\n이메일:',information["emails"])
print('\ndnssec:',information["dnssec"])

