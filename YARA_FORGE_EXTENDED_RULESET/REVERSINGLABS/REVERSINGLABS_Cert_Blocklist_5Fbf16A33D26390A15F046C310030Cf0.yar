import "pe"

rule REVERSINGLABS_Cert_Blocklist_5Fbf16A33D26390A15F046C310030Cf0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "620c04df-e613-5319-aa00-646c7e0c8031"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10014-L10030"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "24bee3563e0867ef6702e7f57bbce7075f766410650ae5ce1e2e8c7b14a3eaca"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MACHINES SATU MARE SRL" and pe.signatures[i].serial=="5f:bf:16:a3:3d:26:39:0a:15:f0:46:c3:10:03:0c:f0" and 1638390070<=pe.signatures[i].not_after)
}
