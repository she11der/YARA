rule SIGNATURE_BASE_Webshell_B374K_Php
{
	meta:
		description = "PHP Webshells Github Archive - file b374k.php.php"
		author = "Florian Roth (Nextron Systems)"
		id = "73eb7d8d-14bb-5bc2-90b2-90b6bd603bd1"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5707-L5722"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "04c99efd187cf29dc4e5603c51be44170987bce2"
		logic_hash = "f44ecdcf327cf417a90a91c8d23f6137b80c2006bea2ca2e214f2bfdf5793771"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "// encrypt your password to md5 here http://kerinci.net/?x=decode" fullword
		$s6 = "// password (default is: b374k)"
		$s8 = "//******************************************************************************"
		$s9 = "// b374k 2.2" fullword
		$s10 = "eval(\"?>\".gzinflate(base64_decode("

	condition:
		3 of them
}
