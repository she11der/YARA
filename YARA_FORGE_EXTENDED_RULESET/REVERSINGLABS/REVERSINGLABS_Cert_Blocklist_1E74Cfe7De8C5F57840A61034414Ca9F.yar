import "pe"

rule REVERSINGLABS_Cert_Blocklist_1E74Cfe7De8C5F57840A61034414Ca9F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d7fd0c3f-0292-5d27-b8e6-559b829440b4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6424-L6442"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d82220d908283f1707ec15882503b02cb8dc80095279a9e7d6cbdd113c25d8ae"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Insta Software Solution Inc." and (pe.signatures[i].serial=="00:1e:74:cf:e7:de:8c:5f:57:84:0a:61:03:44:14:ca:9f" or pe.signatures[i].serial=="1e:74:cf:e7:de:8c:5f:57:84:0a:61:03:44:14:ca:9f") and 1601733106<=pe.signatures[i].not_after)
}
