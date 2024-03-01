import "pe"

rule REVERSINGLABS_Cert_Blocklist_Cfad6Be1D823B4Eacb803B720F525A7D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "844e295f-b22f-5eb0-9f98-0d6e574d2954"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9148-L9166"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d8005774e6011d8198039a6588834cd0b13dd728103b63c3ea8b6e0dc3878f05"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sistema LLC" and (pe.signatures[i].serial=="00:cf:ad:6b:e1:d8:23:b4:ea:cb:80:3b:72:0f:52:5a:7d" or pe.signatures[i].serial=="cf:ad:6b:e1:d8:23:b4:ea:cb:80:3b:72:0f:52:5a:7d") and 1627430400<=pe.signatures[i].not_after)
}
