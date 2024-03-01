import "pe"

rule REVERSINGLABS_Cert_Blocklist_04422F12037Bc2032521Dbb6Ae02Ea0E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing GovRAT malware."
		author = "ReversingLabs"
		id = "0dc659e8-1f3b-5130-a776-dd9e4141f5f3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1508-L1524"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "381d749d24121d6634656fd33adcda5c3e500ee77a6333f525f351a2ee589e2c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Open Source Developer, Muhammad Lee" and pe.signatures[i].serial=="04:42:2f:12:03:7b:c2:03:25:21:db:b6:ae:02:ea:0e" and 1404172799<=pe.signatures[i].not_after)
}
