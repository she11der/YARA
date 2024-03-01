rule SIGNATURE_BASE_Unknown_0F06C5D1B32F4994C3B3Abf8Bb76D5468F105167 : FILE
{
	meta:
		description = "Detects a web shell"
		author = "Florian Roth (Nextron Systems)"
		id = "efd09da2-f232-5a21-99c8-dc2bf00baa73"
		date = "2016-09-10"
		modified = "2023-12-05"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L9610-L9625"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6f4bdf8aecd527335c29a8e964c7d8688c3e77419595d3fd10a6cf3704711816"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6362372850ac7455fa9461ed0483032a1886543f213a431f81a2ac76d383b47e"

	strings:
		$s1 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/libraries/lola.php\" ;" fullword ascii
		$s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
		$s3 = "fwrite($fp,base64_decode('" ascii

	condition:
		( uint16(0)==0x6324 and filesize <2KB and all of them )
}
