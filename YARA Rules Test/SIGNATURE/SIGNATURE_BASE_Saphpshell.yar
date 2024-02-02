rule SIGNATURE_BASE_Saphpshell
{
	meta:
		description = "Webshells Auto-generated - file saphpshell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "42bcd739-714e-5dbf-a3a1-929f3d16ed6f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7511-L7522"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "d7bba8def713512ddda14baf9cd6889a"
		logic_hash = "24d558292a709bb29334b1acdc53cdb6c5bc6803caec527edcacd6a19f6dc7c9"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<td><input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['command']?>"

	condition:
		all of them
}