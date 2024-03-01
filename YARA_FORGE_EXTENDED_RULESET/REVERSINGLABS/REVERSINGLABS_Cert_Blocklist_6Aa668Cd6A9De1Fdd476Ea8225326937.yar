import "pe"

rule REVERSINGLABS_Cert_Blocklist_6Aa668Cd6A9De1Fdd476Ea8225326937 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bfff2210-8545-594d-8674-243e57e3dd09"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1780-L1796"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "706e16995af40a6c9176dcbca07fb406f2efe4d47dbd9629d1a6b1ab1d09b045"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BSCP LIMITED" and pe.signatures[i].serial=="6a:a6:68:cd:6a:9d:e1:fd:d4:76:ea:82:25:32:69:37" and 1441583999<=pe.signatures[i].not_after)
}
