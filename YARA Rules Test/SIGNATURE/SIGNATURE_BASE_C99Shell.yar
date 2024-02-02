rule SIGNATURE_BASE_C99Shell
{
	meta:
		description = "Webshells Auto-generated - file c99shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8692-L8703"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "90b86a9c63e2cd346fe07cea23fbfc56"
		logic_hash = "a0fcc43a80ac4d059aea36da8b4b5a81c99a54f7c66c521697805ae890d66fe8"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<br />Input&nbsp;URL:&nbsp;&lt;input&nbsp;name=\\\"uploadurl\\\"&nbsp;type=\\\"text\\\"&"

	condition:
		all of them
}