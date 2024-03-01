import "pe"

rule REVERSINGLABS_Cert_Blocklist_0218Ebfd5A9Bfd55D2F661F0D18D1D71 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d03619c7-c4e8-57bd-a19e-1452ab7a76df"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12066-L12082"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4aabe3beab0055b6ef8f6114c5236940f5693b44e94efd14132b450bb9232c03"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "REI LUX UK LIMITED" and pe.signatures[i].serial=="02:18:eb:fd:5a:9b:fd:55:d2:f6:61:f0:d1:8d:1d:71" and 1608508800<=pe.signatures[i].not_after)
}
