import "pe"

rule REVERSINGLABS_Cert_Blocklist_Fc7065Abf8303Fb472B8Af85918F5C24 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1aebd2be-b22c-5102-a449-27025f61cce6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16100-L16118"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f57ae32d7efd9cd4c0a207897e30b871dc32405c5b9ad844c9bb7eee4827cc5a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DIG IN VISION SP Z O O" and (pe.signatures[i].serial=="00:fc:70:65:ab:f8:30:3f:b4:72:b8:af:85:91:8f:5c:24" or pe.signatures[i].serial=="fc:70:65:ab:f8:30:3f:b4:72:b8:af:85:91:8f:5c:24") and 1604361600<=pe.signatures[i].not_after)
}
