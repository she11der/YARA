import "pe"

rule REVERSINGLABS_Cert_Blocklist_3696883055975D571199C6B5D48F3Cd5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f68338f9-8614-5793-981d-70547dbc65ce"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5328-L5344"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d6f77b9ca928167341a35b83e353886d4db8dfcecf45cde0f0f93d65059b5200"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Korist Networks Incorporated" and pe.signatures[i].serial=="36:96:88:30:55:97:5d:57:11:99:c6:b5:d4:8f:3c:d5" and 1600069289<=pe.signatures[i].not_after)
}
