import "pe"

rule REVERSINGLABS_Cert_Blocklist_E0134C41E7Eda6863C4Eee5B003976Dd : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "395c14fd-2fec-53ad-bc8e-2dd4bb3522d2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14674-L14692"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fbe34baf52e3fa7d7cdfcfaef9b8851c4cbeb46d17eeade61750e59cf0c13291"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "5000 LIMITED" and (pe.signatures[i].serial=="00:e0:13:4c:41:e7:ed:a6:86:3c:4e:ee:5b:00:39:76:dd" or pe.signatures[i].serial=="e0:13:4c:41:e7:ed:a6:86:3c:4e:ee:5b:00:39:76:dd") and 1528070400<=pe.signatures[i].not_after)
}
