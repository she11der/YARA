import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Fba0E19919Ac50D700Ba60250D02C8B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8828c863-2800-5f66-968e-96a41a071218"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9020-L9036"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8c803111df930056bdc3ef7560f07bf4d255b93286d01ecc55f790e72565ba5d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Diamartis" and pe.signatures[i].serial=="7f:ba:0e:19:91:9a:c5:0d:70:0b:a6:02:50:d0:2c:8b" and 1623196800<=pe.signatures[i].not_after)
}
