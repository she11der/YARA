import "pe"

rule REVERSINGLABS_Cert_Blocklist_3D2580E89526F7852B570654Efd9A8Bf : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing LockerGoga ransomware."
		author = "ReversingLabs"
		id = "0514759c-2d10-5b29-aa2f-d16eb45b2816"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2952-L2968"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0f46fcfc8ee06756646899450daa254d3e5261bdc5c2339f20d01971608fff7b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MIKL LIMITED" and pe.signatures[i].serial=="3d:25:80:e8:95:26:f7:85:2b:57:06:54:ef:d9:a8:bf" and 1529888400<=pe.signatures[i].not_after)
}
