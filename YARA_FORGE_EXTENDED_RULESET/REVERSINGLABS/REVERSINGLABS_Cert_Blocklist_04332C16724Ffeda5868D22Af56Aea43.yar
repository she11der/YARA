import "pe"

rule REVERSINGLABS_Cert_Blocklist_04332C16724Ffeda5868D22Af56Aea43 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1e5a2708-2875-50ab-af6b-3be91f38e13f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6772-L6788"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6b62d5c7a3c6e3096797cd2f515d86045fa77682638bda44175d05c5b6c5bbc0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bespoke Software Solutions Limited" and pe.signatures[i].serial=="04:33:2c:16:72:4f:fe:da:58:68:d2:2a:f5:6a:ea:43" and 1597971601<=pe.signatures[i].not_after)
}
