import "pe"

rule REVERSINGLABS_Cert_Blocklist_36A77D37E68E02Fd3D043C7197E044Ca : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "721e48fb-3046-5b2d-8ad9-ae340e598794"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14022-L14038"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fc13ac5880cc2c8eac9ff8d09f6c5c2055b2de54d460a284936a4f6cd78192e8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Direct Systems Ltd" and pe.signatures[i].serial=="36:a7:7d:37:e6:8e:02:fd:3d:04:3c:71:97:e0:44:ca" and 1515542400<=pe.signatures[i].not_after)
}
