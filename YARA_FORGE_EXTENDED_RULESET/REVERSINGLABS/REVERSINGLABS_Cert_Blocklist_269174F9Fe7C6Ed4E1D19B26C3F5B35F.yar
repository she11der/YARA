import "pe"

rule REVERSINGLABS_Cert_Blocklist_269174F9Fe7C6Ed4E1D19B26C3F5B35F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fbcf1f18-f612-5516-9a67-2564de76c456"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3866-L3882"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "95c9720d6311c2fe7026b6cac092d59967479e6c9382eac1d26f7745efa92860"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GO ONLINE d.o.o." and pe.signatures[i].serial=="26:91:74:f9:fe:7c:6e:d4:e1:d1:9b:26:c3:f5:b3:5f" and 1586386919<=pe.signatures[i].not_after)
}
