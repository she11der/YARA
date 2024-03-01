import "pe"

rule REVERSINGLABS_Cert_Blocklist_8385684419Ab26A3F2640B1496E1Fe94 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "03e861a0-156e-5366-a312-dc2aa73b0393"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8396-L8414"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "24f75badc335160a8053a4c7e8bbd8ddbd3266c3a18059a937d5989df97ae9d9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CAUSE FOR CHANGE LTD" and (pe.signatures[i].serial=="00:83:85:68:44:19:ab:26:a3:f2:64:0b:14:96:e1:fe:94" or pe.signatures[i].serial=="83:85:68:44:19:ab:26:a3:f2:64:0b:14:96:e1:fe:94") and 1612137600<=pe.signatures[i].not_after)
}
