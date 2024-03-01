import "pe"

rule REVERSINGLABS_Cert_Blocklist_0108Cbaee60728F5Bf06E45A56D6F170 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2be3a0d2-2c6a-5c66-856a-d3a70a490ba3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9366-L9382"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "52027548e20c819e73ea5e9afd87faaca4498bc39e54dd30ad99a24e3ace57fd"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE6\\xAD\\xA6\\xE6\\xB1\\x89\\xE4\\xB8\\x9C\\xE6\\xB9\\x96\\xE6\\x96\\xB0\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE5\\xBC\\x80\\xE5\\x8F\\x91\\xE5\\x8C\\xBA" and pe.signatures[i].serial=="01:08:cb:ae:e6:07:28:f5:bf:06:e4:5a:56:d6:f1:70" and 1605680260<=pe.signatures[i].not_after)
}
