import "pe"

rule REVERSINGLABS_Cert_Blocklist_3Bcaed3Ef678F2F9Bf38D09E149B8D70 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0aea5110-569b-5d9c-a2ce-a6a9fe75b58e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4538-L4554"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "dbf85cbd1d92823287749dac312f95576900753f60a694347b31b1e3aaa288a8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "StarY Media Inc." and pe.signatures[i].serial=="3b:ca:ed:3e:f6:78:f2:f9:bf:38:d0:9e:14:9b:8d:70" and 1599091200<=pe.signatures[i].not_after)
}
