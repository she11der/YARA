import "pe"

rule REVERSINGLABS_Cert_Blocklist_540Cea639D5D48669B7F2F64 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bfc514b6-43ef-5343-b5f2-d39168ba3e8d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3772-L3788"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3d3774f10ff9949ea13a7892662438b84b3eb895fc986092649fa9b192170d48"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CENTR MBP LLC" and pe.signatures[i].serial=="54:0c:ea:63:9d:5d:48:66:9b:7f:2f:64" and 1570871755<=pe.signatures[i].not_after)
}
