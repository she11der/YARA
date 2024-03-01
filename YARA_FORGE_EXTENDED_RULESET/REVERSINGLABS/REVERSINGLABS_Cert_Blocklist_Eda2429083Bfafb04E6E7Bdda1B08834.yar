import "pe"

rule REVERSINGLABS_Cert_Blocklist_Eda2429083Bfafb04E6E7Bdda1B08834 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0f5852c4-7866-5e12-97e9-c73972def6c5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10352-L10370"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4f7d5c6929fe364c8868fddb28dd7bbf7cdcf3896d57836466af1a538190d11c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OWLNET LIMITED" and (pe.signatures[i].serial=="00:ed:a2:42:90:83:bf:af:b0:4e:6e:7b:dd:a1:b0:88:34" or pe.signatures[i].serial=="ed:a2:42:90:83:bf:af:b0:4e:6e:7b:dd:a1:b0:88:34") and 1625011200<=pe.signatures[i].not_after)
}
