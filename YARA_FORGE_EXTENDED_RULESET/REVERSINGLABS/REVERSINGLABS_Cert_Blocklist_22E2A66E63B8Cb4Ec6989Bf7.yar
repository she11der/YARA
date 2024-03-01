import "pe"

rule REVERSINGLABS_Cert_Blocklist_22E2A66E63B8Cb4Ec6989Bf7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5c028a6c-890c-54f1-aea2-ac04ce654907"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13638-L13654"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2099c508d1fd986f34f14aa396a5aaa136e2cdd2226099acdca9c14f6f6342eb"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sivi Technology Limited" and pe.signatures[i].serial=="22:e2:a6:6e:63:b8:cb:4e:c6:98:9b:f7" and 1466995365<=pe.signatures[i].not_after)
}
