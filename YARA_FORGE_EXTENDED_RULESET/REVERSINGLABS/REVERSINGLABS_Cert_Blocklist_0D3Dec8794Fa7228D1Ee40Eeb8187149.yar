import "pe"

rule REVERSINGLABS_Cert_Blocklist_0D3Dec8794Fa7228D1Ee40Eeb8187149 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "54e9ec00-d054-521b-b60b-81efe3a8ce12"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13258-L13274"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "20084dc0b069d65755f859f5aef4be5599d1f066ba006199d3ce803b0d8f041e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Financial Security Institute, Inc." and pe.signatures[i].serial=="0d:3d:ec:87:94:fa:72:28:d1:ee:40:ee:b8:18:71:49" and 1582675200<=pe.signatures[i].not_after)
}
