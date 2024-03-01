import "pe"

rule REVERSINGLABS_Cert_Blocklist_Dc992Ea8E6Bb4926931Df656D5Eef8A0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "506b217e-ea82-5f14-880e-b6c0cbb001fb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15608-L15626"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2b261624677a1c4a1ef539106bedcef30f272fda3d833d4c8095e9797d592e1f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MEGAPOLISELIT, OOO" and (pe.signatures[i].serial=="00:dc:99:2e:a8:e6:bb:49:26:93:1d:f6:56:d5:ee:f8:a0" or pe.signatures[i].serial=="dc:99:2e:a8:e6:bb:49:26:93:1d:f6:56:d5:ee:f8:a0") and 1497916800<=pe.signatures[i].not_after)
}
