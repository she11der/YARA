import "pe"

rule REVERSINGLABS_Cert_Blocklist_19Beff8A6C129663E5E8C18953Dc1F67 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "300d9e11-9283-500e-9716-5b628ef41853"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7504-L7520"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0ec031c781ebad7447cfc53ce791aacc8f24e38f039c84e2ee547de64729ae76"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CULNADY LTD LTD" and pe.signatures[i].serial=="19:be:ff:8a:6c:12:96:63:e5:e8:c1:89:53:dc:1f:67" and 1608163200<=pe.signatures[i].not_after)
}
