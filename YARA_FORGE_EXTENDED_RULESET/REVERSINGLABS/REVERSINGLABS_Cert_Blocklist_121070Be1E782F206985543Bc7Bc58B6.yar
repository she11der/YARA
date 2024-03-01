import "pe"

rule REVERSINGLABS_Cert_Blocklist_121070Be1E782F206985543Bc7Bc58B6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3f5eee11-4106-5923-9563-84f81199bea0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10516-L10532"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a5d603cf64c8a16fa12daf9c6b5d0850e6145fb39b38442ed724ec0f849b8be9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Prod Can Holdings Inc." and pe.signatures[i].serial=="12:10:70:be:1e:78:2f:20:69:85:54:3b:c7:bc:58:b6" and 1647820800<=pe.signatures[i].not_after)
}
