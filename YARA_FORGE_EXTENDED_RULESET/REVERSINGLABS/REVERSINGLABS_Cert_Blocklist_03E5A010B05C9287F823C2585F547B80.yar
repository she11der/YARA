import "pe"

rule REVERSINGLABS_Cert_Blocklist_03E5A010B05C9287F823C2585F547B80 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "14ad79c7-f669-59a6-94d1-978a13fbb337"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1126-L1142"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1d57b640ee313ad4d53dc64ce4df3e4ed57976e7750cfd80d62bf9982d964d26"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MOCOMSYS INC" and pe.signatures[i].serial=="03:e5:a0:10:b0:5c:92:87:f8:23:c2:58:5f:54:7b:80" and 1385423999<=pe.signatures[i].not_after)
}
