import "pe"

rule REVERSINGLABS_Cert_Blocklist_Bb26B7B6634D5Db548C437B5085B01C1 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "443a876a-dfd7-5a9e-bb15-a44a53363494"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4086-L4104"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "58d574b196f84416eb04000205cd8f4817618003f2948bb0eb7d951c282ef6ff"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO \"IT Mott\"" and (pe.signatures[i].serial=="00:bb:26:b7:b6:63:4d:5d:b5:48:c4:37:b5:08:5b:01:c1" or pe.signatures[i].serial=="bb:26:b7:b6:63:4d:5d:b5:48:c4:37:b5:08:5b:01:c1") and 1591919307<=pe.signatures[i].not_after)
}
