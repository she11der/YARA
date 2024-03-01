import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3533080B377F80C0Ea826B2492Bf767B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "42d2328e-742e-5c35-aa14-3b42442543ce"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1127-L1138"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a7adb9190be4a9cf60adf4b55c8abaa80e01224ea834fc05705afef37703899e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2afcc4cdee842d80bf7b6406fb503957c8a09b4d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\xA8\\x9C\\xE8\\xBF\\xAA\\xD0\\x91\\xE8\\xBF\\xAA\\xD0\\x91\\xE5\\xA8\\x9C\\xE5\\x93\\xA6\\xE5\\xB0\\xBA\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xD0\\x91\\xE8\\xBF\\xAA\\xD0\\x91\\xE5\\xB0\\xBA\\xE5\\xB0\\xBA\\xE8\\xBF\\xAA\\xE5\\x93\\xA6\\xE8\\xBF\\xAA\\xE5\\x8B\\x92\\xD0\\x91\\xE5\\x8B\\x92\\xE5\\x93\\xA6\\xE5\\x8B\\x92\\xE5\\x93\\xA6\\xD0\\x91" and pe.signatures[i].serial=="35:33:08:0b:37:7f:80:c0:ea:82:6b:24:92:bf:76:7b")
}
