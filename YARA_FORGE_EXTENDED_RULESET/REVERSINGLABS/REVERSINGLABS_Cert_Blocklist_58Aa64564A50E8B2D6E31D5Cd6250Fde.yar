import "pe"

rule REVERSINGLABS_Cert_Blocklist_58Aa64564A50E8B2D6E31D5Cd6250Fde : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "00e096f6-2955-5936-9a75-f537c2da3621"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8264-L8280"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f6b50ebf707b67650fe832d81c6fe8d2411cd83432ef94432d181db0c29aa48b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Foreground" and pe.signatures[i].serial=="58:aa:64:56:4a:50:e8:b2:d6:e3:1d:5c:d6:25:0f:de" and 1609002028<=pe.signatures[i].not_after)
}
