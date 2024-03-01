rule SIGNATURE_BASE_Venom_Rootkit : FILE
{
	meta:
		description = "Venom Linux Rootkit"
		author = "Florian Roth (Nextron Systems)"
		id = "fedc6fa9-7dfb-5e54-a7bf-9a16f96d6886"
		date = "2017-01-12"
		modified = "2023-12-05"
		reference = "https://security.web.cern.ch/security/venom.shtml"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_venom_linux_rootkit.yar#L10-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0b2211edc6737e9da3e43bec9ef823e80c6bd6463adbb10d6839e9914aed22ac"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "%%VENOM%CTRL%MODE%%" ascii fullword
		$s2 = "%%VENOM%OK%OK%%" ascii fullword
		$s3 = "%%VENOM%WIN%WN%%" ascii fullword
		$s4 = "%%VENOM%AUTHENTICATE%%" ascii fullword
		$s5 = ". entering interactive shell" ascii fullword
		$s6 = ". processing ltun request" ascii fullword
		$s7 = ". processing rtun request" ascii fullword
		$s8 = ". processing get request" ascii fullword
		$s9 = ". processing put request" ascii fullword
		$s10 = "venom by mouzone" ascii fullword
		$s11 = "justCANTbeSTOPPED" ascii fullword

	condition:
		filesize <4000KB and 2 of them
}
