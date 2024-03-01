import "pe"

rule REVERSINGLABS_Cert_Blocklist_5B1F9Ec88D185631Ab032Dbfd5166C0D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "51c596cd-3033-51ef-914f-310d2bbfbd5f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10752-L10768"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "dec9d43c6911deb5f35c45692bfd6ef47f85d955f5e59041e58a1f0d2fc306e3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TOPFLIGHT GROUP LIMITED" and pe.signatures[i].serial=="5b:1f:9e:c8:8d:18:56:31:ab:03:2d:bf:d5:16:6c:0d" and 1656028800<=pe.signatures[i].not_after)
}
