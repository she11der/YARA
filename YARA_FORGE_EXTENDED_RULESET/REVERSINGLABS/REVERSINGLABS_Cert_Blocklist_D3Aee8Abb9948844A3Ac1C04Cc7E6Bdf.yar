import "pe"

rule REVERSINGLABS_Cert_Blocklist_D3Aee8Abb9948844A3Ac1C04Cc7E6Bdf : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6da50886-7f15-5565-9a1a-f6fb25a729ac"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10180-L10198"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3f3f1d5c871d2b73627d4281ac5bcd08799fb47f94155e82795d97c87de35e40"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HOUSE 9A s.r.o" and (pe.signatures[i].serial=="00:d3:ae:e8:ab:b9:94:88:44:a3:ac:1c:04:cc:7e:6b:df" or pe.signatures[i].serial=="d3:ae:e8:ab:b9:94:88:44:a3:ac:1c:04:cc:7e:6b:df") and 1640822400<=pe.signatures[i].not_after)
}
