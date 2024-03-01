import "pe"

rule REVERSINGLABS_Cert_Blocklist_6716A9C195987D5Cfe53A094779461E7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fbd05f8b-3289-565c-a5f4-a1514d06ae37"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13330-L13346"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "648fd70432a791b3e589f5eda1b1510045b465623914a9762ff3dfb4a3e022f8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Inter Technologies Ltd." and pe.signatures[i].serial=="67:16:a9:c1:95:98:7d:5c:fe:53:a0:94:77:94:61:e7" and 1169424000<=pe.signatures[i].not_after)
}
