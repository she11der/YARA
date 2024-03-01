import "pe"

rule REVERSINGLABS_Cert_Blocklist_7903870184E18A80899740845A15E2B2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a55bed5b-906f-5c9d-bddd-b4d53d6351de"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15846-L15862"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ad32491b463d0b3b4c85ed78e81bb69802e5f90ae835f73e270b28f02b36f840"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Qool Aid, LLC" and pe.signatures[i].serial=="79:03:87:01:84:e1:8a:80:89:97:40:84:5a:15:e2:b2" and 1079654400<=pe.signatures[i].not_after)
}
