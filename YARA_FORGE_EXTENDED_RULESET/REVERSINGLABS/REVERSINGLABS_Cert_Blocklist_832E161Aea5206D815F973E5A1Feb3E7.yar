import "pe"

rule REVERSINGLABS_Cert_Blocklist_832E161Aea5206D815F973E5A1Feb3E7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing SeedLocker ransomware."
		author = "ReversingLabs"
		id = "ecaa250b-d4ac-5cc9-9e5e-5d6f45db18ad"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2988-L3006"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "da908de031c78aa012809988e44dea564d32b88b65a2010925c1af85d578a68a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Project NSRM Ltd" and (pe.signatures[i].serial=="00:83:2e:16:1a:ea:52:06:d8:15:f9:73:e5:a1:fe:b3:e7" or pe.signatures[i].serial=="83:2e:16:1a:ea:52:06:d8:15:f9:73:e5:a1:fe:b3:e7") and 1549830060<=pe.signatures[i].not_after)
}
