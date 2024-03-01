import "pe"

rule REVERSINGLABS_Cert_Blocklist_256541E204619033F8B09F9Eb7C88Ef8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d4a5eb19-2964-5d3a-b4c5-ee4396e76814"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1416-L1432"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e33cedf1dd24ac73f77461de0cef25cad57909be2a69469fec450ead7da85c65"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HON HAI PRECISION INDUSTRY CO. LTD." and pe.signatures[i].serial=="25:65:41:e2:04:61:90:33:f8:b0:9f:9e:b7:c8:8e:f8" and 1424303999<=pe.signatures[i].not_after)
}
