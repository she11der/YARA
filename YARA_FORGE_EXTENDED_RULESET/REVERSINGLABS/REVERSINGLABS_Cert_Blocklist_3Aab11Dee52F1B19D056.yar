import "pe"

rule REVERSINGLABS_Cert_Blocklist_3Aab11Dee52F1B19D056 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "c6334520-7f93-59d0-8a22-721b928c14d1"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1074-L1089"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1f1215143dc828596e6d7eeff99983755b17eaeb3ab9d7643abdbb48e9957c78"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Microsoft Enforced Licensing Intermediate PCA" and pe.signatures[i].serial=="3a:ab:11:de:e5:2f:1b:19:d0:56")
}
