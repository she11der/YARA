import "pe"

rule REVERSINGLABS_Cert_Blocklist_A617E23D6Ca8F34E2F7413Cd299Fc72B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3ffb592c-eec5-51b1-9840-b6b72269fc31"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9958-L9976"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f307a0b598f0876c003aa43db50e024698b6f93931e626c085f98553c14ec2ae"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "EXPRESS BOOKS LTD" and (pe.signatures[i].serial=="00:a6:17:e2:3d:6c:a8:f3:4e:2f:74:13:cd:29:9f:c7:2b" or pe.signatures[i].serial=="a6:17:e2:3d:6c:a8:f3:4e:2f:74:13:cd:29:9f:c7:2b") and 1636971821<=pe.signatures[i].not_after)
}
