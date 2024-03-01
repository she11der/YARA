import "pe"

rule REVERSINGLABS_Cert_Blocklist_B63E4299D0B0E2Dcdaeb976167A23235 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "44af31cc-e0c9-5f3f-9645-a0453bc81e62"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14894-L14912"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "da7415d0bc0245dea6a4ec325da5140c79c723c20fb7c04ff14f59a3089a5c88"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Baltservis LLC" and (pe.signatures[i].serial=="00:b6:3e:42:99:d0:b0:e2:dc:da:eb:97:61:67:a2:32:35" or pe.signatures[i].serial=="b6:3e:42:99:d0:b0:e2:dc:da:eb:97:61:67:a2:32:35") and 1604102400<=pe.signatures[i].not_after)
}
