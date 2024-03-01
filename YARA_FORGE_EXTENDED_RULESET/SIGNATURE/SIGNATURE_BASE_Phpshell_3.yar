rule SIGNATURE_BASE_Phpshell_3
{
	meta:
		description = "Webshells Auto-generated - file phpshell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "2f0ddfef-b3b5-592b-a9fb-fae4d825d0af"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8943-L8955"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e8693a2d4a2ffea4df03bb678df3dc6d"
		logic_hash = "b86fa40fd7bbcae86926182882faa226530e44c20bc611b8433a7da7f012106c"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>"
		$s5 = "      echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";"

	condition:
		all of them
}
