import "pe"

rule REVERSINGLABS_Cert_Blocklist_45E27C4Dfa5E6175566A13B1B6Ddf3F5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b4ab6397-5e15-5eb3-9f5d-658c5e3a7e3d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14494-L14510"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9bcbb84207984b259463482f094bf0f3815f0d74317b6b864dab44769ff5e7e8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Selig Michael Irfan" and pe.signatures[i].serial=="45:e2:7c:4d:fa:5e:61:75:56:6a:13:b1:b6:dd:f3:f5" and 1465474542<=pe.signatures[i].not_after)
}
