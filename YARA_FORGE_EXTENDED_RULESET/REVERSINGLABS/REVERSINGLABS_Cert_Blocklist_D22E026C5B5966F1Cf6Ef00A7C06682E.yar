import "pe"

rule REVERSINGLABS_Cert_Blocklist_D22E026C5B5966F1Cf6Ef00A7C06682E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a72a0001-a272-506d-b610-c028ed8ac6da"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9920-L9938"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "33a05d46b40ffdf49bfa5facca41ebdf6bedcabc1cb1f5b9bf2d043ad1c869b0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMCERT, LLC" and (pe.signatures[i].serial=="00:d2:2e:02:6c:5b:59:66:f1:cf:6e:f0:0a:7c:06:68:2e" or pe.signatures[i].serial=="d2:2e:02:6c:5b:59:66:f1:cf:6e:f0:0a:7c:06:68:2e") and 1636456620<=pe.signatures[i].not_after)
}
