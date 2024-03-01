import "pe"

rule REVERSINGLABS_Cert_Blocklist_1B248C8508042D36Bbd5D92D189C61D8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4ad05207-10d1-53c5-8383-a3c71a447ed6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10954-L10970"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2c063d0878a8bf6cd637e1dac2cb9164beb52c951e01858a7c3c9c4c1a853f54"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Digital Robin Limited" and pe.signatures[i].serial=="1b:24:8c:85:08:04:2d:36:bb:d5:d9:2d:18:9c:61:d8" and 1663171218<=pe.signatures[i].not_after)
}
