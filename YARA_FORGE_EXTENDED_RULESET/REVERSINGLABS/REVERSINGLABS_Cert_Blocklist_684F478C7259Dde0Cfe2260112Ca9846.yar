import "pe"

rule REVERSINGLABS_Cert_Blocklist_684F478C7259Dde0Cfe2260112Ca9846 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "840af428-47e0-529e-9db9-8ab9c968f2e3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3996-L4012"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "59654ba1df27029a04ef3b1a1bb54f6c15b727f2013923a11a729752b8829743"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LLC \"IP EM\"" and pe.signatures[i].serial=="68:4f:47:8c:72:59:dd:e0:cf:e2:26:01:12:ca:98:46" and 1584981648<=pe.signatures[i].not_after)
}
