import "pe"

rule REVERSINGLABS_Cert_Blocklist_790177A54209D55560A55Db97C5900D6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "cc49f477-269a-55af-8344-39d2f24c1e7f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4780-L4796"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "07c8e21fe604b481beebae784eb49e32bebee70e749581a55313bfbc757752e2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MAK GmbH" and pe.signatures[i].serial=="79:01:77:a5:42:09:d5:55:60:a5:5d:b9:7c:59:00:d6" and 1594080000<=pe.signatures[i].not_after)
}
