import "pe"

rule REVERSINGLABS_Cert_Blocklist_Aa146Bff4B832Bdbfe30B84580356763 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "90fab567-f39f-5d0b-b0d9-a93693a05a01"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2614-L2632"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "37abe7a4fd773fd34f5d7dbe725ba4edcfb8ebb501dc41f386b8b0629161051f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yancheng Peoples Information Technology Service Co., Ltd" and (pe.signatures[i].serial=="00:aa:14:6b:ff:4b:83:2b:db:fe:30:b8:45:80:35:67:63" or pe.signatures[i].serial=="aa:14:6b:ff:4b:83:2b:db:fe:30:b8:45:80:35:67:63") and 1295481599<=pe.signatures[i].not_after)
}
