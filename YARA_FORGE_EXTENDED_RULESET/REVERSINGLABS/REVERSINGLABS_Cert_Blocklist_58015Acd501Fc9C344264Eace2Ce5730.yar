import "pe"

rule REVERSINGLABS_Cert_Blocklist_58015Acd501Fc9C344264Eace2Ce5730 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "28a56bcf-1f13-5478-a6d5-7595464da198"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16302-L16318"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7c1bec5059d40fc326bb08775888ed169abc746228eeb42c897f479992c5acab"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Nanjing Ranyi Technology Co., Ltd. " and pe.signatures[i].serial=="58:01:5a:cd:50:1f:c9:c3:44:26:4e:ac:e2:ce:57:30" and 1352246400<=pe.signatures[i].not_after)
}
