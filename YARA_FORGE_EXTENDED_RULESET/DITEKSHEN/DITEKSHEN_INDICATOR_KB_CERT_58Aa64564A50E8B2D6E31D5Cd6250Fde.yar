import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_58Aa64564A50E8B2D6E31D5Cd6250Fde : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b6eff323-241a-5f11-837f-bfacdc547d89"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4496-L4507"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "7383dfc8b22379dc69cd1d93d2da40e177ba1e3b0b8b8891afb8ce594269d170"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a7b43a5190e6a72c68e20f661f69ddc24b5a2561"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Foreground" and pe.signatures[i].serial=="58:aa:64:56:4a:50:e8:b2:d6:e3:1d:5c:d6:25:0f:de")
}
