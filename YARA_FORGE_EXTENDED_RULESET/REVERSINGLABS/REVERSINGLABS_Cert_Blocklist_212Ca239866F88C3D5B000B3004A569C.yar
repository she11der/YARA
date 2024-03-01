import "pe"

rule REVERSINGLABS_Cert_Blocklist_212Ca239866F88C3D5B000B3004A569C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b433cddc-25c3-5627-99b5-ff9bc7fa73ed"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16890-L16906"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "23ab2343b17dce74fb4166a690ca5dd300b3ed20d3a6b43b922f456410d3035d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "XECURE LAB CO., LTD." and pe.signatures[i].serial=="21:2c:a2:39:86:6f:88:c3:d5:b0:00:b3:00:4a:56:9c" and 1347840000<=pe.signatures[i].not_after)
}
