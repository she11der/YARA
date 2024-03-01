import "pe"

rule REVERSINGLABS_Cert_Blocklist_6Fc143Ba34Cabf1De7A4C7F8F4Cdad6D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "546692ed-2506-56ad-b678-e74b857380a3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12782-L12798"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ffe25e4478a2245d4e5b330bb9300fb6cb48afb0fe3bd72bd62a589eeee3fe89"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "World Telecom International Inc." and pe.signatures[i].serial=="6f:c1:43:ba:34:ca:bf:1d:e7:a4:c7:f8:f4:cd:ad:6d" and 1147046400<=pe.signatures[i].not_after)
}
