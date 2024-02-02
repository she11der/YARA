rule SIGNATURE_BASE_PHP_Shell
{
	meta:
		description = "Webshells Auto-generated - file shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "08dff4db-3b1c-5702-a8c9-efaedf83c4ff"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8143-L8155"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "45e8a00567f8a34ab1cccc86b4bc74b9"
		logic_hash = "a62061b2fa851f5798158198e26f188408f3f37dca69a85ca155777c0b8407ee"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "AR8iROET6mMnrqTpC6W1Kp/DsTgxNby9H1xhiswfwgoAtED0y6wEXTihoAtICkIX6L1+vTUYWuWz"
		$s11 = "1HLp1qnlCyl5gko8rDlWHqf8/JoPKvGwEm9Q4nVKvEh0b0PKle3zeFiJNyjxOiVepMSpflJkPv5s"

	condition:
		all of them
}