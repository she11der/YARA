rule SIGNATURE_BASE_Txt_Asp1 : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file asp1.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "b00ab02c-c767-568c-be99-6cc731c3f1dc"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L514-L530"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "95934d05f0884e09911ea9905c74690ace1ef653"
		logic_hash = "77a4409b852d24228b0e1701f1ccc2abe3930c2c7240a43796b23042e706d9bf"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
		$s2 = "autoLoginEnable=WSHShell.RegRead(autoLoginPath & autoLoginEnableKey)" fullword ascii
		$s3 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
		$s4 = "szTempFile = server.mappath(\"cmd.txt\")" fullword ascii

	condition:
		filesize <70KB and 2 of them
}
