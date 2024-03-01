import "pe"

rule REVERSINGLABS_Cert_Blocklist_6401831B46588B9D872B02076C3A7B00 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "61b67e68-9e15-5848-b12a-437a0ad8399e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7088-L7104"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cb84b27391fa0260061bc5444039967e83f2134f7b56f9cccf6a421d4a65a577"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ACTIV GROUP ApS" and pe.signatures[i].serial=="64:01:83:1b:46:58:8b:9d:87:2b:02:07:6c:3a:7b:00" and 1615507200<=pe.signatures[i].not_after)
}
