import "pe"

rule REVERSINGLABS_Cert_Blocklist_C79F817F082986Bef3209F6723C8Da97 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b3978831-57d6-5f25-a271-fa4f449d37b3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11422-L11440"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a5960f4c2ed768ccc5779d3754f51463c7b14a3a887c690944add23fba464f1a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Al-Faris group d.o.o." and (pe.signatures[i].serial=="00:c7:9f:81:7f:08:29:86:be:f3:20:9f:67:23:c8:da:97" or pe.signatures[i].serial=="c7:9f:81:7f:08:29:86:be:f3:20:9f:67:23:c8:da:97") and 1616371200<=pe.signatures[i].not_after)
}
