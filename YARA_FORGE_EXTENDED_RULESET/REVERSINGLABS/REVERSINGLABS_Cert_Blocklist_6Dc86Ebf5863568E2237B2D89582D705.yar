import "pe"

rule REVERSINGLABS_Cert_Blocklist_6Dc86Ebf5863568E2237B2D89582D705 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "24741dc7-6252-5964-a69f-bef4b2dfe1a7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16026-L16042"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f24cdf890bd0b51a83ca333c37bc22068ab1f7e7ef36b36d94a133773097bd37"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dening Hu" and pe.signatures[i].serial=="6d:c8:6e:bf:58:63:56:8e:22:37:b2:d8:95:82:d7:05" and 1471305600<=pe.signatures[i].not_after)
}
