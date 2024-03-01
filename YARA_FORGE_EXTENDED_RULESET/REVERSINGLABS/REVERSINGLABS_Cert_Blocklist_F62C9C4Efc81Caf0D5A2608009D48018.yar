import "pe"

rule REVERSINGLABS_Cert_Blocklist_F62C9C4Efc81Caf0D5A2608009D48018 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "176434ae-7162-5b35-91f7-888536250884"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2730-L2748"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "08fcff795297c0608b1a1d71465279cbf76d4dff06de2a2262a58debbb2f9e0d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\x94\\x90\\xE5\\xB1\\xB1\\xE4\\xB8\\x87\\xE4\\xB8\\x9C\\xE6\\xB6\\xA6\\xE6\\x92\\xAD\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (pe.signatures[i].serial=="00:f6:2c:9c:4e:fc:81:ca:f0:d5:a2:60:80:09:d4:80:18" or pe.signatures[i].serial=="f6:2c:9c:4e:fc:81:ca:f0:d5:a2:60:80:09:d4:80:18") and 1292889599<=pe.signatures[i].not_after)
}
