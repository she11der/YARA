import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ece6Cbf67Dc41635A5E5D075F286Af23 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3e451a5a-835b-572d-ab17-ff52d3614a86"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6368-L6386"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f560e6f4a65eaac8db1d8accb0748de17048e66ccf989468e6350a3ec1d70dc8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THRANE AGENTUR ApS" and (pe.signatures[i].serial=="00:ec:e6:cb:f6:7d:c4:16:35:a5:e5:d0:75:f2:86:af:23" or pe.signatures[i].serial=="ec:e6:cb:f6:7d:c4:16:35:a5:e5:d0:75:f2:86:af:23") and 1603369254<=pe.signatures[i].not_after)
}
