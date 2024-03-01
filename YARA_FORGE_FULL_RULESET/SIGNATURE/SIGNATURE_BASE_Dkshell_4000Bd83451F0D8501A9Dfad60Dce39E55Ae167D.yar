rule SIGNATURE_BASE_Dkshell_4000Bd83451F0D8501A9Dfad60Dce39E55Ae167D : FILE
{
	meta:
		description = "Detects a web shell"
		author = "Florian Roth (Nextron Systems)"
		id = "804f7229-1440-5a2e-91cd-a58a38b22aa9"
		date = "2016-09-10"
		modified = "2023-12-05"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L9557-L9575"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "26d586e32d1b0b7800b4b61f592dadc3dd0583628e4cd3fa4e24e02067077da5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "51a16b09520a3e063adf10ff5192015729a5de1add8341a43da5326e626315bd"

	strings:
		$x1 = "DK Shell - Took the Best made it Better..!!" fullword ascii
		$x2 = "preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x61\\x73\\x65\\x36\\x" ascii
		$x3 = "echo '<b>Sw Bilgi<br><br>'.php_uname().'<br></b>';" fullword ascii
		$s1 = "echo '<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">';" fullword ascii
		$s9 = "$x = $_GET[\"x\"];" fullword ascii

	condition:
		( uint16(0)==0x3f3c and filesize <200KB and 1 of ($x*)) or (3 of them )
}
