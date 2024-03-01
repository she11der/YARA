import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_B0009Bb062F52Eb6001Ba79606De243D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "41293f0b-604a-5993-8b05-9ca639828eec"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3217-L3228"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "111a08d62f483daf23220e7044cc291b6ea6922746d48934f72a892b7dfd762b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c89f06937d24b7f13be5edba5e0e2f4e05bc9b13"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fbfdddcfabc" and pe.signatures[i].serial=="b0:00:9b:b0:62:f5:2e:b6:00:1b:a7:96:06:de:24:3d")
}
