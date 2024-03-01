import "pe"

rule REVERSINGLABS_Cert_Blocklist_0772B4D1D63233D2B8771997Bc8Da5C4 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fe602ac3-fa34-5056-a2cc-5ae9de728559"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11218-L11234"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "30586a643b29f3c943b3f35bb1639c5b9fa48ecbd776775086e35af502aa4a7a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Maya logistika d.o.o." and pe.signatures[i].serial=="07:72:b4:d1:d6:32:33:d2:b8:77:19:97:bc:8d:a5:c4" and 1637971201<=pe.signatures[i].not_after)
}
