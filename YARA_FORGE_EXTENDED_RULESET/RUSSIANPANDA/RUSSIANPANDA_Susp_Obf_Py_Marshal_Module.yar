rule RUSSIANPANDA_Susp_Obf_Py_Marshal_Module : FILE
{
	meta:
		description = "Detects Obfuscated Code Using Python Marshal Module"
		author = "RussianPanda"
		id = "23ed45f6-69ba-5027-ad68-4be858fc1f91"
		date = "2024-01-16"
		modified = "2024-01-16"
		reference = "https://www.trendmicro.com/fr_fr/research/23/j/infection-techniques-across-supply-chains-and-codebases.html"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/d6b1e8ac1e4cbf548804bd84e5f63f3f426b9738/Techniques/susp_obf_py_marshal_module.yar#L1-L18"
		license_url = "N/A"
		hash = "d740129ff6bdb65a324eadf4ac8de3893a54306cf2a11712a305ef6247204092"
		logic_hash = "f150fae6d7a4642f714f4620dab65f452e5eb9cb57e9cbea46010aac3ecbb3cb"
		score = 65
		quality = 60
		tags = "FILE"

	strings:
		$s1 = "exec(marshal.loads(zlib.decompress(b'x\\x9c"
		$t2 = "gzip"
		$t3 = "lzma"
		$t4 = "bz2"
		$t5 = "binascii"

	condition:
		$s1 and any of ($t*) and filesize <2MB
}
