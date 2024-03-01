import "pe"

rule REVERSINGLABS_Cert_Blocklist_7C0Be3D14787351E3156F5F37F2B3663 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "14a292da-36c1-5a37-b27e-20c982e44c25"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14822-L14838"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "66c2cd84fccedd2afef00495c49d0c2844e2e5e190e6a859d2970e8ddb4a35c2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Apex Tech, SIA" and pe.signatures[i].serial=="7c:0b:e3:d1:47:87:35:1e:31:56:f5:f3:7f:2b:36:63" and 1523318400<=pe.signatures[i].not_after)
}
