import "pe"

rule REVERSINGLABS_Cert_Blocklist_01E2B4F759811C64379Fca0Be76D2Dce : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "00effc8a-066c-54ff-891e-c635d161b171"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1108-L1124"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0dff7a9f2e152c20427ea231449b942a040e964cb7dad90271d2865290535326"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sony Pictures Entertainment Inc." and pe.signatures[i].serial=="01:e2:b4:f7:59:81:1c:64:37:9f:ca:0b:e7:6d:2d:ce" and 1417651200<=pe.signatures[i].not_after)
}
