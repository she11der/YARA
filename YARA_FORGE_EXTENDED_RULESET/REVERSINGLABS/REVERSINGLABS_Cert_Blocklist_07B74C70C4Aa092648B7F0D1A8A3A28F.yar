import "pe"

rule REVERSINGLABS_Cert_Blocklist_07B74C70C4Aa092648B7F0D1A8A3A28F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f941b7d6-f168-57aa-881a-54679a2b948c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6902-L6918"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "97759fa2e519936115f0493e251f9abc0cce3ada437776a5a370388512235491"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rad-Grad D.O.O." and pe.signatures[i].serial=="07:b7:4c:70:c4:aa:09:26:48:b7:f0:d1:a8:a3:a2:8f" and 1603240965<=pe.signatures[i].not_after)
}
