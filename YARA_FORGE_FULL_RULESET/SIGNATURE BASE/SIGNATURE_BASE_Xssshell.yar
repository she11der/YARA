rule SIGNATURE_BASE_Xssshell
{
	meta:
		description = "Webshells Auto-generated - file xssshell.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "ef89653c-5814-525a-b04e-4326a80f780c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8431-L8442"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "8fc0ffc5e5fbe85f7706ffc45b3f79b4"
		logic_hash = "6b0e602b523f58ec61850b4ba2e69da4fe4bf2833fb45e529785a398445db127"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma"

	condition:
		all of them
}
