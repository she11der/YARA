import "pe"

rule REVERSINGLABS_Cert_Blocklist_230716Bfe915Dd6203B2E2A35674C2Ee : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "849c390e-f81f-558e-88a3-19242c127a56"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14004-L14020"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0197ff46ceb1017488da4383436fd0ddc375904f36cc16c5a8ef21d633ec387c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Jiang Liu" and pe.signatures[i].serial=="23:07:16:bf:e9:15:dd:62:03:b2:e2:a3:56:74:c2:ee" and 1472169600<=pe.signatures[i].not_after)
}
