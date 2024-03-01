import "pe"

rule REVERSINGLABS_Cert_Blocklist_C51F4Cf4D82Bc920421E1Ad93E39D490 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "727aba82-c908-51a6-9f1f-7fd8df424d8c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10256-L10274"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cef717e7fe3eb0fb958d405caaf98fa51b22b150ccbf1286d3b4634e9df81ade"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CUT AHEAD LTD" and (pe.signatures[i].serial=="00:c5:1f:4c:f4:d8:2b:c9:20:42:1e:1a:d9:3e:39:d4:90" or pe.signatures[i].serial=="c5:1f:4c:f4:d8:2b:c9:20:42:1e:1a:d9:3e:39:d4:90") and 1644624000<=pe.signatures[i].not_after)
}
