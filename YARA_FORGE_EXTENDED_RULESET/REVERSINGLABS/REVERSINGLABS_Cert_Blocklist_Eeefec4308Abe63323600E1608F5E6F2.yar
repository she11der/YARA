import "pe"

rule REVERSINGLABS_Cert_Blocklist_Eeefec4308Abe63323600E1608F5E6F2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "265f70f4-f8cf-52cf-8d9b-ddfefb8a1b79"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12628-L12646"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "71ab4bd7e85155bfbc1612941c5f15c409629b116258c38b79bd808512df006a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "YUPITER-STROI, OOO" and (pe.signatures[i].serial=="00:ee:ef:ec:43:08:ab:e6:33:23:60:0e:16:08:f5:e6:f2" or pe.signatures[i].serial=="ee:ef:ec:43:08:ab:e6:33:23:60:0e:16:08:f5:e6:f2") and 1491177600<=pe.signatures[i].not_after)
}
