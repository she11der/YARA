import "pe"

rule REVERSINGLABS_Cert_Blocklist_0C501B8B113209C96C8119Cf7A6B8B79 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9ec73230-10cd-55ad-9ef7-56a875294cab"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13494-L13510"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "dca37fda83650979566fb6ffbedaf713955a3c7f03ecc62e2e155475b7ca00e4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yuanyuan Zhang" and pe.signatures[i].serial=="0c:50:1b:8b:11:32:09:c9:6c:81:19:cf:7a:6b:8b:79" and 1474329600<=pe.signatures[i].not_after)
}
