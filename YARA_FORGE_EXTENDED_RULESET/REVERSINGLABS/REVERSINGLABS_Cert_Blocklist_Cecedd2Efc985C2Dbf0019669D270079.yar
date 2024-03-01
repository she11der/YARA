import "pe"

rule REVERSINGLABS_Cert_Blocklist_Cecedd2Efc985C2Dbf0019669D270079 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "60a3e63c-4f44-5c75-9928-69859d77af3e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14222-L14240"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1dfb5959db6929643126a850de84e54a84d7197518cde475c802987721b71020"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TRANS LTD" and (pe.signatures[i].serial=="00:ce:ce:dd:2e:fc:98:5c:2d:bf:00:19:66:9d:27:00:79" or pe.signatures[i].serial=="ce:ce:dd:2e:fc:98:5c:2d:bf:00:19:66:9d:27:00:79") and 1527811200<=pe.signatures[i].not_after)
}
