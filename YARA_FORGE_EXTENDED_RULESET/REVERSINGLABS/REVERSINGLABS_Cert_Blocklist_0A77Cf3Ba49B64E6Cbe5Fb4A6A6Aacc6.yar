import "pe"

rule REVERSINGLABS_Cert_Blocklist_0A77Cf3Ba49B64E6Cbe5Fb4A6A6Aacc6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4fb06917-ccbd-514c-a936-e337c31c6e65"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L459-L475"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3bebc4a36b57526505167d8f075d468e4775d66c81ce08644c506d9be94efba0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "I.ST.SAN. Srl" and pe.signatures[i].serial=="0a:77:cf:3b:a4:9b:64:e6:cb:e5:fb:4a:6a:6a:ac:c6" and 1371081599<=pe.signatures[i].not_after)
}
