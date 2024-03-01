import "pe"

rule REVERSINGLABS_Cert_Blocklist_3C98B6872Fbb1F4Ae37A4Caa749D24C2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f4cc9c94-eb96-5380-9e12-cab5ec010ab8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11862-L11878"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c534ad306f85e12eca2336e998120deb4ba8d0d63b8331986ec7fe4ac69ba65a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO SMART" and pe.signatures[i].serial=="3c:98:b6:87:2f:bb:1f:4a:e3:7a:4c:aa:74:9d:24:c2" and 1613370100<=pe.signatures[i].not_after)
}
