import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Dd7D4A785990584D8C0837659173272 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d5e3d85b-cc4e-5522-8558-f2703c38c4e6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9312-L9328"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d18a479f07f2bdb890437e2bcb0213abdfb0eb684cdaf17c5eb0583039f2edb4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE9\\x9B\\xB7\\xE7\\xA5\\x9E\\xEF\\xBC\\x88\\xE6\\xAD\\xA6\\xE6\\xB1\\x89\\xEF\\xBC\\x89\\xE4\\xBF\\xA1\\xE6\\x81\\xAF\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="0d:d7:d4:a7:85:99:05:84:d8:c0:83:76:59:17:32:72" and 1586249095<=pe.signatures[i].not_after)
}
