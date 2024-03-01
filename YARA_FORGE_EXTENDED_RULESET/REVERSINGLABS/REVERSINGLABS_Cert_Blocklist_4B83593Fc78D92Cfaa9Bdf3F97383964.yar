import "pe"

rule REVERSINGLABS_Cert_Blocklist_4B83593Fc78D92Cfaa9Bdf3F97383964 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8b5a8a8e-16f5-5098-83e5-72820f4f548a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3598-L3614"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "775e41fc102cbaeb9374984380b0e073de2a0075b9a200f8ab644bd1369ba015"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Kometa" and pe.signatures[i].serial=="4b:83:59:3f:c7:8d:92:cf:aa:9b:df:3f:97:38:39:64" and 1579996800<=pe.signatures[i].not_after)
}
