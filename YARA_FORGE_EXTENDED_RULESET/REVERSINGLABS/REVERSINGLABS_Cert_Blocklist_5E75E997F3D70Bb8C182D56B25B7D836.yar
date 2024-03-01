import "pe"

rule REVERSINGLABS_Cert_Blocklist_5E75E997F3D70Bb8C182D56B25B7D836 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3578b97f-1d87-517a-8ea9-17606017e46a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12666-L12682"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a2c6a57759fb0717951f83a32c00deeae82cad772b6cb7f60fa96232b6b82560"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Primetech Ltd." and pe.signatures[i].serial=="5e:75:e9:97:f3:d7:0b:b8:c1:82:d5:6b:25:b7:d8:36" and 1324252800<=pe.signatures[i].not_after)
}
