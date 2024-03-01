import "pe"

rule REVERSINGLABS_Cert_Blocklist_00Ebaa11D62E2481081820 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "e192d271-b5de-5acc-a04f-02a26d9231ac"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1055-L1072"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2fafc6775ec88b5a1000afbc7234fbef6b03e9eaf866dae660dd2d749996cb5c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Microsoft Enforced Licensing Intermediate PCA" and (pe.signatures[i].serial=="00:eb:aa:11:d6:2e:24:81:08:18:20" or pe.signatures[i].serial=="eb:aa:11:d6:2e:24:81:08:18:20"))
}
