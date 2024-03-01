import "pe"

rule REVERSINGLABS_Cert_Blocklist_422Ab71Ac7Fb125Ad7171B0C99510B0E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "002e344e-a073-5d00-9488-d73fad51c66a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16962-L16978"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7366e5064a9a9f66260730575327e404eadea096ba3f6cf28c83c47bef9bca58"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="42:2a:b7:1a:c7:fb:12:5a:d7:17:1b:0c:99:51:0b:0e" and 1475193600<=pe.signatures[i].not_after)
}
