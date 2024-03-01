rule SIGNATURE_BASE_CN_Honker_Webshell_T00Ls_Lpk_Sethc_V4_Mail : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mail.php"
		author = "Florian Roth (Nextron Systems)"
		id = "2f7d8a4d-9d94-5f23-9768-cc3712678d93"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L230-L245"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0a9b7b438591ee78ee573028cbb805a9dbb9da96"
		logic_hash = "b835a6d0c736116e0a8b277dadbf25c2ac333b0d7937a6f67ed59887c610a57a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "if (!$this->smtp_putcmd(\"AUTH LOGIN\", base64_encode($this->user)))" fullword ascii
		$s2 = "$this->smtp_debug(\"> \".$cmd.\"\\n\");" fullword ascii

	condition:
		filesize <39KB and all of them
}
