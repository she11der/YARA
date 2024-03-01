import "pe"

rule REVERSINGLABS_Cert_Blocklist_Be89936C26Cd0D845074F6B7B47F480C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3ff8149b-4a90-5593-b12a-d815b04fce7e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9822-L9840"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "348df24620bfe6322c410cb593f5caad67492b0b5af234ee89b0411beb4b48f9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Argus Security Maintenance Systems Inc." and (pe.signatures[i].serial=="00:be:89:93:6c:26:cd:0d:84:50:74:f6:b7:b4:7f:48:0c" or pe.signatures[i].serial=="be:89:93:6c:26:cd:0d:84:50:74:f6:b7:b4:7f:48:0c") and 1634235015<=pe.signatures[i].not_after)
}
