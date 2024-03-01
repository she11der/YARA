rule SIGNATURE_BASE_Editserver_EXE
{
	meta:
		description = "Webshells Auto-generated - file EditServer.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "97928144-0112-5288-8f95-acf7a0d56e71"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7364-L7377"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "f945de25e0eba3bdaf1455b3a62b9832"
		logic_hash = "d440669b0c0bf575cf9dea946edf55f724300a4c765e90c631fc1eee062bf006"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "Server %s Have Been Configured"
		$s5 = "The Server Password Exceeds 32 Characters"
		$s8 = "9--Set Procecess Name To Inject DLL"

	condition:
		all of them
}
