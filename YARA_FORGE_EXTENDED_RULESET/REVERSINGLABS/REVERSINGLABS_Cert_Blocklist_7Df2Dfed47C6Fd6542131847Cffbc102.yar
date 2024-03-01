import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Df2Dfed47C6Fd6542131847Cffbc102 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "306444d8-7573-58c6-b6fe-14d701942275"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3360-L3376"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fc6adbfd45ff6ac465aecb3db862421f02170e977fc044017f3ddc306a9f7a37"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AFVIMPEX SRL" and pe.signatures[i].serial=="7d:f2:df:ed:47:c6:fd:65:42:13:18:47:cf:fb:c1:02" and 1567036800<=pe.signatures[i].not_after)
}
