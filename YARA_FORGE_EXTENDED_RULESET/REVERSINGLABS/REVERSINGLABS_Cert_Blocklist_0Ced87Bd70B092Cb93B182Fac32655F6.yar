import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Ced87Bd70B092Cb93B182Fac32655F6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b9e6a35f-08c2-5f29-9bcf-07a3cddf0fbe"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7278-L7294"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4e2c967b9502d9009c61831f019ba19367b866e898ca1246a1099d75ad0eb4d5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Creator Soft Limited" and pe.signatures[i].serial=="0c:ed:87:bd:70:b0:92:cb:93:b1:82:fa:c3:26:55:f6" and 1614816000<=pe.signatures[i].not_after)
}
