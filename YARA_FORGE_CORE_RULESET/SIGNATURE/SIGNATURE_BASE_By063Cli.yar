rule SIGNATURE_BASE_By063Cli
{
	meta:
		description = "Webshells Auto-generated - file by063cli.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "9b4a4842-e084-53e8-90fb-603ba034b7df"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8768-L8780"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "49ce26eb97fd13b6d92a5e5d169db859"
		logic_hash = "c89159b73232bc8fd7430b3330009f4b3eb25b9511515bc9b4cd433f7a67f30e"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "#popmsghello,are you all right?"
		$s4 = "connect failed,check your network and remote ip."

	condition:
		all of them
}
