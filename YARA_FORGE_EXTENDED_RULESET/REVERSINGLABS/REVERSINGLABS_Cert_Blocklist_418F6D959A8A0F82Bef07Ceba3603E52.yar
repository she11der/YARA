import "pe"

rule REVERSINGLABS_Cert_Blocklist_418F6D959A8A0F82Bef07Ceba3603E52 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ecfb72ef-04c4-55b6-b9e0-e95053e03425"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5844-L5862"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6c13c5e85d6e053319193d1d94f216eeec64405c86d15971419078a1ce6c8ac9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OORT inc." and (pe.signatures[i].serial=="00:41:8f:6d:95:9a:8a:0f:82:be:f0:7c:eb:a3:60:3e:52" or pe.signatures[i].serial=="41:8f:6d:95:9a:8a:0f:82:be:f0:7c:eb:a3:60:3e:52") and 1601928240<=pe.signatures[i].not_after)
}
