import "pe"

rule REVERSINGLABS_Cert_Blocklist_3054F940C931Bad7B238A24376C6A5Cc : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e5643d08-5957-58b0-8b46-d5e339dfba9c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9940-L9956"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "21c8e8f10d1e4b9eb917c86ac868de2afcd5776a9c1d59149df1d07d8c3e14b9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "POLE CLEAN LTD" and pe.signatures[i].serial=="30:54:f9:40:c9:31:ba:d7:b2:38:a2:43:76:c6:a5:cc" and 1637030220<=pe.signatures[i].not_after)
}
