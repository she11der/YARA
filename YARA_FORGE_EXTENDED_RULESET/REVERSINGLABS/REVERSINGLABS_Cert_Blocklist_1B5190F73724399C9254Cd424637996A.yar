import "pe"

rule REVERSINGLABS_Cert_Blocklist_1B5190F73724399C9254Cd424637996A : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "dfb08450-c35c-5b7b-9d04-2c9a6af9bcf8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1037-L1053"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "08f287ccda93e03a7e796d5625ab35ef0de782d07e5db4e2264f612fc5ebaa21"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Microsoft Corporation" and pe.signatures[i].serial=="1b:51:90:f7:37:24:39:9c:92:54:cd:42:46:37:99:6a" and 980812799<=pe.signatures[i].not_after)
}
