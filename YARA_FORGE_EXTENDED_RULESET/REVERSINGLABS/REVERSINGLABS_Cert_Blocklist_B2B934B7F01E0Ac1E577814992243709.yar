import "pe"

rule REVERSINGLABS_Cert_Blocklist_B2B934B7F01E0Ac1E577814992243709 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "19930e7b-09cb-5c04-b838-3d8d73ba194b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16744-L16762"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "37b254ab76d144c09cc7b622dba59f5e372bf01ae12ce260a06143abb52062f6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MS CORP SOFTWARE LTD" and (pe.signatures[i].serial=="00:b2:b9:34:b7:f0:1e:0a:c1:e5:77:81:49:92:24:37:09" or pe.signatures[i].serial=="b2:b9:34:b7:f0:1e:0a:c1:e5:77:81:49:92:24:37:09") and 1590710400<=pe.signatures[i].not_after)
}
