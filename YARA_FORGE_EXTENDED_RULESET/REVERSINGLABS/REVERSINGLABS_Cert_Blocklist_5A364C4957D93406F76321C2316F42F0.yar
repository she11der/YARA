import "pe"

rule REVERSINGLABS_Cert_Blocklist_5A364C4957D93406F76321C2316F42F0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "49e36ae5-25f0-5e1d-82f0-c7ada2b4d914"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10880-L10896"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fe3a2b906debb3f03e6a403829fca02c751754e9a02442a962c66defb84aed83"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Board Game Bucket Ltd" and pe.signatures[i].serial=="5a:36:4c:49:57:d9:34:06:f7:63:21:c2:31:6f:42:f0" and 1661337307<=pe.signatures[i].not_after)
}
