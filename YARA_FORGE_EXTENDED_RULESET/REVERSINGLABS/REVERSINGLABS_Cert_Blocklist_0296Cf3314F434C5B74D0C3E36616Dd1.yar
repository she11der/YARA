import "pe"

rule REVERSINGLABS_Cert_Blocklist_0296Cf3314F434C5B74D0C3E36616Dd1 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ae7d8c3c-0ac8-5ea5-8013-97ccb2ace4e4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13584-L13600"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "acf3b7460c79fa71c1b131b26a40bbc286c9da0a5fe7071bbe8b386a3ca91de4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="02:96:cf:33:14:f4:34:c5:b7:4d:0c:3e:36:61:6d:d1" and 1474934400<=pe.signatures[i].not_after)
}
