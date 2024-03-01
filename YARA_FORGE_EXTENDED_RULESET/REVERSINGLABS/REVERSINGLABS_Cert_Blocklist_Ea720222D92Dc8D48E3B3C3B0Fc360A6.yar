import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ea720222D92Dc8D48E3B3C3B0Fc360A6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8415406b-ede8-5404-8208-34eb649f7325"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7940-L7958"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c60e1ccf178f03f930a3bc41e9a92be20df0362f067ed1fcfc7c93627a056d75"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CAVANAGH NETS LIMITED" and (pe.signatures[i].serial=="00:ea:72:02:22:d9:2d:c8:d4:8e:3b:3c:3b:0f:c3:60:a6" or pe.signatures[i].serial=="ea:72:02:22:d9:2d:c8:d4:8e:3b:3c:3b:0f:c3:60:a6") and 1608640280<=pe.signatures[i].not_after)
}
