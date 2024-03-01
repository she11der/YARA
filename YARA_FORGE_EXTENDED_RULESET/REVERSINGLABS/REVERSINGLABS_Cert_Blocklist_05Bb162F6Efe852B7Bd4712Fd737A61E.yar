import "pe"

rule REVERSINGLABS_Cert_Blocklist_05Bb162F6Efe852B7Bd4712Fd737A61E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "82b2198e-140a-54d0-afa8-ad89980c7899"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9204-L9220"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d2fcbce0826c1478338827376d2c7869e5b38dc6d5e737a2f986600c6f71b1e6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Wellpro Impact Solutions Oy" and pe.signatures[i].serial=="05:bb:16:2f:6e:fe:85:2b:7b:d4:71:2f:d7:37:a6:1e" and 1628726400<=pe.signatures[i].not_after)
}
