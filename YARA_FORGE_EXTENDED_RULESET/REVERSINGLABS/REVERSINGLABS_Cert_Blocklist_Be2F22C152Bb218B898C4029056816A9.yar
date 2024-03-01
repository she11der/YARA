import "pe"

rule REVERSINGLABS_Cert_Blocklist_Be2F22C152Bb218B898C4029056816A9 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d5ca9d9d-e80f-56c1-90b7-ef931e61ba92"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16080-L16098"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cd99e4d97d9a60f409cf072bbae254486c307ae3cb6e34c5cd9648c972615f36"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Marts GmbH" and (pe.signatures[i].serial=="00:be:2f:22:c1:52:bb:21:8b:89:8c:40:29:05:68:16:a9" or pe.signatures[i].serial=="be:2f:22:c1:52:bb:21:8b:89:8c:40:29:05:68:16:a9") and 1676246400<=pe.signatures[i].not_after)
}
