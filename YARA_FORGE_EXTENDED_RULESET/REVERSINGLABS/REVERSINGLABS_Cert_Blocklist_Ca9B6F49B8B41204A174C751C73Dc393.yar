import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ca9B6F49B8B41204A174C751C73Dc393 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d09658e4-44e4-5c10-a866-ba486000f1b6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16356-L16374"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0b6558a7a1b78d471aaadced959ba91e411df50e3cc08e447fe9bd97f9e5cced"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CodeDance Ltd" and (pe.signatures[i].serial=="00:ca:9b:6f:49:b8:b4:12:04:a1:74:c7:51:c7:3d:c3:93" or pe.signatures[i].serial=="ca:9b:6f:49:b8:b4:12:04:a1:74:c7:51:c7:3d:c3:93") and 1654646400<=pe.signatures[i].not_after)
}
